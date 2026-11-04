import { useState } from 'react'
import type { FormEvent, ReactElement } from 'react'
import type { AccountState } from '@shared/account-auth'
import './AccountGate.css'

export default function AccountGate({ state, retry }: { state: AccountState; retry(): Promise<void> }): ReactElement {
  const [view, setView] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    if (busy) return
    if (view === 'register' && password !== confirmation) { setMessage('两次输入的密码不一致。'); return }
    setBusy(true)
    setMessage('')
    try {
      const result = view === 'register'
        ? await window.api.registerAccount({ username, password })
        : await window.api.loginAccount({ username, password })
      if (!result.ok) setMessage(result.message)
      else { setPassword(''); setConfirmation('') }
    } catch { setMessage('无法联系账号服务，请稍后重试。') }
    finally { setBusy(false) }
  }
  return <main className="account-gate">
    <div className="account-gate__drag" aria-hidden="true" />
    <section className="account-gate__card" aria-label="客户端账号登录">
      <div className="account-gate__logo" aria-hidden="true">W</div>
      <h1>Web2Term Chat</h1>
      <p className="account-gate__intro">登录客户端账号后，继续使用 ChatGPT。</p>
      {state.status === 'checking' ? (
        <p className="account-gate__notice" role="status">正在核验这台电脑的登录资格…</p>
      ) : (
        <>
          <div className="account-gate__tabs" role="tablist" aria-label="登录方式">
            <button type="button" role="tab" aria-selected={view === 'login'} className={view === 'login' ? 'is-active' : ''}
              onClick={() => { setView('login'); setMessage('') }}>登录</button>
            <button type="button" role="tab" aria-selected={view === 'register'} className={view === 'register' ? 'is-active' : ''}
              onClick={() => { setView('register'); setMessage('') }}>注册</button>
          </div>
          <form onSubmit={event => void submit(event)} className="account-gate__form">
            <label htmlFor="account-username">用户名</label>
            <input id="account-username" autoFocus autoComplete="username" required maxLength={32} minLength={3}
              spellCheck={false} value={username} placeholder="3—32 位英文、数字或下划线" onChange={event => setUsername(event.target.value.toLowerCase())} />
            <label htmlFor="account-password">密码</label>
            <div className="account-gate__password">
              <input id="account-password" autoComplete={view === 'register' ? 'new-password' : 'current-password'}
                required minLength={10} maxLength={128} type={showPassword ? 'text' : 'password'}
                placeholder="至少 10 位密码" value={password} onChange={event => setPassword(event.target.value)} />
              <button type="button" onClick={() => setShowPassword(current => !current)} aria-label={showPassword ? '隐藏密码' : '显示密码'}>{showPassword ? '隐藏' : '显示'}</button>
            </div>
            {view === 'register' ? <>
              <label htmlFor="account-confirm">确认密码</label>
              <input id="account-confirm" autoComplete="new-password" required minLength={10} maxLength={128}
                type={showPassword ? 'text' : 'password'} placeholder="再次输入密码"
                value={confirmation} onChange={event => setConfirmation(event.target.value)} />
            </> : null}
            {state.status === 'unavailable' ? (
              <div role="alert" className="account-gate__error">
                {state.message || '账号服务器暂时不可用。'}
                <button type="button" disabled={busy} onClick={() => void retry()}>重新连接</button>
              </div>
            ) : null}
            {message ? <p className="account-gate__error" role="alert">{message}</p> : null}
            <button className="account-gate__submit" type="submit" disabled={busy}>
              {busy ? '正在验证…' : view === 'register' ? '注册并绑定这台电脑' : '登录'}
            </button>
          </form>
          <p className="account-gate__device-note">每个用户名只能绑定一台电脑。首次注册时自动绑定；换电脑需管理员解绑，同一电脑再次登录不需要重新绑定。</p>
          <p className="account-gate__footer">这是客户端账号，与 OpenAI / ChatGPT 账号独立。聊天网页仍需正常登录 OpenAI。</p>
        </>
      )}
    </section>
  </main>
}
