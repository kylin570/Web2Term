/** Separate product login. Never confuse this account with the OpenAI web login. */
export type AccountStatus = 'checking' | 'signed-out' | 'signed-in' | 'unavailable'
export interface AccountState {
  status: AccountStatus
  username: string | null
  message: string
  server: string
}
export interface AccountCredentials { username: string; password: string }
export type AccountResult = { ok: true; state: AccountState } | { ok: false; code: string; message: string }

export const ACCOUNT_ERRORS: Record<string, string> = {
  INVALID_USERNAME: '用户名必须以小写字母开头，只能包含小写字母、数字或下划线，长度 3—32 位。',
  INVALID_PASSWORD: '密码须为 10—128 个字符。',
  INVALID_CREDENTIALS: '用户名或密码错误。',
  USERNAME_TAKEN: '这个用户名已被注册。',
  DEVICE_BOUND: '该账号已绑定另一台电脑。请联系管理员解绑后，在新电脑登录。',
  ACCOUNT_LOCKED: '密码连续错误次数过多，请 10 分钟后重试。',
  CHALLENGE_EXPIRED: '登录校验已过期，请重试。',
  TOO_MANY_REQUESTS: '请求过于频繁，请稍后重试。',
  REGISTRATION_DISABLED: '注册入口已关闭，请联系管理员。',
  SESSION_EXPIRED: '登录已失效，请重新登录。',
  SERVICE_UNAVAILABLE: '登录服务暂时不可用，请稍后重试。',
  SERVER_UNREACHABLE: '无法连接账号服务器，请检查网络后重试。',
  SECURE_STORAGE: '当前系统无法安全保存登录凭据，请检查系统钥匙串或凭据管理器。',
  BAD_RESPONSE: '登录服务响应异常，请稍后重试。'
}
