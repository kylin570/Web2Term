import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { safeStorage } from 'electron'
import { ACCOUNT_ERRORS } from '../shared/account-auth'
import type { AccountCredentials, AccountResult, AccountState } from '../shared/account-auth'
import { DEFAULT_ACCOUNT_SERVER } from '../shared/account-server'

interface StoredToken { username: string; token: string; expiresAt: number }
interface ServerReply { ok: boolean; code?: string; nonce?: string; username?: string; token?: string; expiresAt?: number }

export class DeviceAccountService {
  private readonly keyFile: string
  private readonly tokenFile: string
  private readonly server: string
  private privateKeyPem: string | null = null
  private token: StoredToken | null = null
  private heartbeat: ReturnType<typeof setInterval> | null = null
  private state: AccountState
  private requestBusy = false
  constructor(dataDir: string, private readonly changed: (state: AccountState) => void) {
    this.keyFile = join(dataDir, 'account-device-key.bin')
    this.tokenFile = join(dataDir, 'account-session.bin')
    const configured = (process.env['WEB2TERM_ACCOUNT_URL'] || DEFAULT_ACCOUNT_SERVER).replace(/\/+$/, '')
    const url = new URL(configured)
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) {
      throw new Error('账号服务器必须使用 HTTPS。')
    }
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('账号服务器 URL 格式不正确。')
    this.server = url.origin
    this.state = { status: 'checking', username: null, message: '', server: this.server }
    mkdirSync(dataDir, { recursive: true })
  }

  getState(): AccountState { return { ...this.state } }
  isAuthenticated(): boolean { return this.state.status === 'signed-in' && !!this.token && this.token.expiresAt > Math.floor(Date.now() / 1000) }
  private publish(status: AccountState['status'], username: string | null = null, message = ''): AccountState {
    this.state = { status, username, message, server: this.server }
    this.changed(this.getState())
    return this.getState()
  }
  private canEncrypt(): boolean {
    return safeStorage.isEncryptionAvailable() && (process.platform !== 'linux' || safeStorage.getSelectedStorageBackend() !== 'basic_text')
  }
  private readSecure(file: string): string | null {
    if (!existsSync(file)) return null
    if (!this.canEncrypt()) throw new Error('SECURE_STORAGE')
    return safeStorage.decryptString(readFileSync(file))
  }
  private writeSecure(file: string, value: string): void {
    if (!this.canEncrypt()) throw new Error('SECURE_STORAGE')
    const temporary = file + '.' + randomUUID() + '.tmp'
    writeFileSync(temporary, safeStorage.encryptString(value), { mode: 0o600, flag: 'wx' })
    renameSync(temporary, file)
  }
  private devicePrivateKey(): string {
    if (this.privateKeyPem) return this.privateKeyPem
    const existing = this.readSecure(this.keyFile)
    if (existing) {
      // Reject corrupted keys instead of silently generating a second device identity.
      createPrivateKey(existing)
      this.privateKeyPem = existing
      return existing
    }
    const keys = generateKeyPairSync('ed25519')
    const pem = keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    this.writeSecure(this.keyFile, pem)
    this.privateKeyPem = pem
    return pem
  }
  private devicePublic(): string {
    const key = createPublicKey(createPrivateKey(this.devicePrivateKey())).export({ format: 'jwk' })
    if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || !key.x) throw new Error('INVALID_DEVICE')
    return Buffer.from(key.x, 'base64url').toString('base64')
  }
  private signature(message: string): string {
    return sign(null, Buffer.from(message, 'utf8'), createPrivateKey(this.devicePrivateKey())).toString('base64')
  }
  private async request(path: string, body: Record<string, unknown>, token?: string): Promise<ServerReply> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers.Authorization = 'Bearer ' + token
    let response: Response
    try {
      response = await fetch(this.server + path, {
        method: 'POST', headers, body: JSON.stringify(body), redirect: 'error',
        signal: AbortSignal.timeout(12000), cache: 'no-store'
      })
    } catch {
      throw new Error('SERVER_UNREACHABLE')
    }
    let result: unknown
    try { result = await response.json() } catch { throw new Error('BAD_RESPONSE') }
    if (typeof result !== 'object' || result === null || !('ok' in result) || typeof result.ok !== 'boolean') throw new Error('BAD_RESPONSE')
    const reply = result as ServerReply
    if (!reply.ok || !response.ok) throw new Error(typeof reply.code === 'string' ? reply.code : 'BAD_RESPONSE')
    return reply
  }
  private async authenticateSession(token: StoredToken): Promise<ServerReply> {
    const timestamp = Math.floor(Date.now() / 1000)
    const path = '/v1/auth/session'
    return this.request(path, {
      timestamp, signature: this.signature('web2term-session-v1\n' + path + '\n' + timestamp + '\n' + token.token)
    }, token.token)
  }
  private result(error: unknown): AccountResult {
    const code = error instanceof Error ? error.message : 'BAD_RESPONSE'
    return { ok: false, code, message: ACCOUNT_ERRORS[code] || '登录请求失败，请稍后重试。' }
  }

  async restore(): Promise<AccountState> {
    try {
      const raw = this.readSecure(this.tokenFile)
      if (!raw) return this.publish('signed-out')
      const token: unknown = JSON.parse(raw)
      if (!token || typeof token !== 'object' || !('token' in token) || !('username' in token) || !('expiresAt' in token)
        || typeof token.token !== 'string' || typeof token.username !== 'string' || typeof token.expiresAt !== 'number') {
        throw new Error('BAD_RESPONSE')
      }
      this.token = token as StoredToken
      return this.validate()
    } catch (error) {
      if (error instanceof Error && error.message === 'SECURE_STORAGE') return this.publish('unavailable', null, ACCOUNT_ERRORS.SECURE_STORAGE)
      this.token = null
      return this.publish('signed-out', null, ACCOUNT_ERRORS.SESSION_EXPIRED)
    }
  }
  async validate(): Promise<AccountState> {
    const token = this.token
    if (!token) return this.publish('signed-out')
    try {
      const reply = await this.authenticateSession(token)
      if (reply.username !== token.username || typeof reply.expiresAt !== 'number') throw new Error('BAD_RESPONSE')
      token.expiresAt = reply.expiresAt
      return this.publish('signed-in', token.username)
    } catch (error) {
      if (error instanceof Error && ['SESSION_EXPIRED', 'INVALID_SIGNATURE', 'ACCOUNT_EXPIRED'].includes(error.message)) {
        this.token = null
        return this.publish('signed-out', null, ACCOUNT_ERRORS[error.message] || ACCOUNT_ERRORS.SESSION_EXPIRED)
      }
      const code = error instanceof Error ? error.message : 'SERVER_UNREACHABLE'
      return this.publish('unavailable', null, ACCOUNT_ERRORS[code] || ACCOUNT_ERRORS.SERVER_UNREACHABLE)
    }
  }
  async credentials(action: 'register' | 'login', input: AccountCredentials): Promise<AccountResult> {
    if (this.requestBusy) return { ok: false, code: 'BUSY', message: '正在处理上一次请求。' }
    this.requestBusy = true
    try {
      const username = input.username.trim().toLowerCase()
      if (!/^[a-z][a-z0-9_]{2,31}$/.test(username)) throw new Error('INVALID_USERNAME')
      if (input.password.length < 10 || input.password.length > 128) throw new Error('INVALID_PASSWORD')
      const challenge = await this.request('/v1/auth/challenge', {})
      if (!challenge.nonce) throw new Error('BAD_RESPONSE')
      const response = await this.request('/v1/auth/' + action, {
        username, password: input.password, nonce: challenge.nonce,
        devicePublic: this.devicePublic(),
        signature: this.signature('web2term-auth-v1\n' + action + '\n' + username + '\n' + challenge.nonce)
      })
      if (!response.token || response.username !== username || typeof response.expiresAt !== 'number') throw new Error('BAD_RESPONSE')
      this.writeSecure(this.tokenFile, JSON.stringify({ username, token: response.token, expiresAt: response.expiresAt }))
      this.token = { username, token: response.token, expiresAt: response.expiresAt }
      return { ok: true, state: this.publish('signed-in', username) }
    } catch (error) { return this.result(error) }
    finally { this.requestBusy = false }
  }
  async logout(): Promise<AccountState> {
    const previous = this.token
    this.token = null
    // Clear local credentials first, even when offline; logout never resets device binding.
    this.writeSecure(this.tokenFile, '')
    const state = this.publish('signed-out')
    if (previous) {
      const path = '/v1/auth/logout'
      const timestamp = Math.floor(Date.now() / 1000)
      void this.request(path, {
        timestamp, signature: this.signature('web2term-session-v1\n' + path + '\n' + timestamp + '\n' + previous.token)
      }, previous.token).catch(() => {})
    }
    return state
  }
  startMonitoring(): void {
    if (this.heartbeat) return
    this.heartbeat = setInterval(() => { if (this.token) void this.validate() }, 5 * 60_000)
    this.heartbeat.unref?.()
  }
  dispose(): void { if (this.heartbeat) clearInterval(this.heartbeat); this.heartbeat = null }
}