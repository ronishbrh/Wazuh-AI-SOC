
import { useEffect, useRef, useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  Bot,
  Send,
  Plus,
  PanelLeftClose,
  Wifi,
  WifiOff,
  LockKeyhole,
  LoaderCircle,
  UserRound,
} from 'lucide-react'
import './App.css'


const initialMessage = {
  id: 1,
  role: 'assistant',
  text: 'Hello! I’m your AI assistant. How can I help you today?',
  status: 'success',
}

function App() {
  const [messages, setMessages] = useState([initialMessage])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [apiOnline, setApiOnline] = useState(null)
  const [userId, setUserId] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const bottomRef = useRef(null)
  const inputRef = useRef(null)

  const [sessionRestricted, setSessionRestricted] = useState(false)

  const [analystPassword, setAnalystPassword] = useState('')
  const [releaseMessage, setReleaseMessage] = useState('')
  const [releasing, setReleasing] = useState(false)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  useEffect(() => {
    let cancelled = false

    async function initializeSession() {
      try {
        let response = await fetch('/api/session_status', {
          credentials: 'same-origin',
        })

        if (!response.ok) {
          response = await fetch('/api/session', {
            method: 'POST',
            credentials: 'same-origin',
          })

          if (!response.ok) {
            throw new Error('Could not create a server session')
          }
        }

        response = await fetch('/api/session_status', {
          credentials: 'same-origin',
        })

        if (!response.ok) {
          throw new Error('Could not verify the session')
        }

        const data = await response.json()

        if (!cancelled) {
          setUserId(data.user_id)
          setApiOnline(true)

          if (data.status === 'active_response') {
            setSessionRestricted(true)
            setMessages([{
              id: Date.now(),
              role: 'assistant',
              text: data.reply,
              status: 'active_response',
            }])
          } else {
            setSessionRestricted(false)
          }
        }
      } catch (error) {
        console.error('Session initialization failed:', error)
        if (!cancelled) setApiOnline(false)
      }
    }

    initializeSession()

    return () => {
      cancelled = true
    }
  }, [])




  async function sendMessage(event) {
    event?.preventDefault()

    const text = input.trim()
    if (!text || loading) return

    const userMessage = {
      id: Date.now(),
      role: 'user',
      text,
    }

    setMessages((current) => [...current, userMessage])
    setInput('')
    setLoading(true)

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'same-origin',
        body: JSON.stringify({ text }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || `API returned ${response.status}`)
      }

      setApiOnline(true)
      if (data.status === 'active_response') {
        setSessionRestricted(true)
      }
      setMessages((current) => [
        ...current,
        {
          id: Date.now() + 1,
          role: 'assistant',
          text: data.reply || 'The API returned an empty response.',
          status: data.status || 'unknown',
        },
      ])
    } catch (error) {
      setApiOnline(false)
      setMessages((current) => [
        ...current,
        {
          id: Date.now() + 1,
          role: 'assistant',
          text: `I couldn't reach the chatbot API. ${error.message}. Check that FastAPI is running and the Vite proxy is configured correctly.`,
          status: 'connection_error',
        },
      ])
    } finally {
      setLoading(false)
      inputRef.current?.focus()
    }
  }


  async function releaseSession(event) {
    event.preventDefault()
    if (!analystPassword || releasing) return

    setReleasing(true)
    setReleaseMessage('')

    try {
      const response = await fetch('/api/analyst/release', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Analyst-Password': analystPassword,
        },
        credentials: 'same-origin',
        body: JSON.stringify({ user_id: userId }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          response.status === 401
            ? 'Analyst authentication failed.'
            : data.detail || 'Release request failed.'
        )
      }

      setSessionRestricted(false)
      setAnalystPassword('')
      setReleaseMessage('Session released successfully.')
      setMessages([
        {
          id: Date.now(),
          role: 'assistant',
          text: 'The SOC analyst released this session. You may send messages again.',
          status: 'success',
        },
      ])
    } catch (error) {
      setReleaseMessage(error.message)
    } finally {
      setReleasing(false)
    }
  }


  function newChat() {
    setMessages([initialMessage])
    setInput('')
    inputRef.current?.focus()
  }

  function statusDetails(status) {
    switch (status) {
      case 'security_violation':
        return {
          label: 'Security policy triggered',
          className: 'security',
          Icon: ShieldAlert,
        }
      case 'active_response':
        return {
          label: 'Session restricted',
          className: 'restricted',
          Icon: LockKeyhole,
        }
      case 'connection_error':
        return {
          label: 'Connection error',
          className: 'error',
          Icon: WifiOff,
        }
      case 'success':
        return {
          label: 'Request processed',
          className: 'success',
          Icon: ShieldCheck,
        }
      default:
        return null
    }
  }

  return (
    <div className={`app-shell ${sidebarOpen ? '' : 'sidebar-collapsed'}`}>
      <aside className="sidebar">
        <div className="sidebar-top">
          <div className="brand">
            <div className="brand-icon">
              <ShieldCheck size={21} />
            </div>
            {sidebarOpen && (
              <div className="brand-copy">
                <span className="brand-name">Sentinel AI</span>
                <span className="brand-subtitle">Security lab</span>
              </div>
            )}
          </div>

          <button
            className="icon-button sidebar-toggle"
            onClick={() => setSidebarOpen((open) => !open)}
            aria-label="Toggle sidebar"
          >
            <PanelLeftClose size={19} />
          </button>
        </div>

        <button className="new-chat-button" onClick={newChat}>
          <Plus size={18} />
          {sidebarOpen && <span>New conversation</span>}
        </button>

        {sidebarOpen && (
          <>
            <div className="sidebar-section-label">WORKSPACE</div>
            <div className="workspace-card">
              <div className="workspace-icon">
                <Bot size={18} />
              </div>
              <div className="workspace-copy">
                <span>AI Assistant</span>
                <small>Security monitoring demo</small>
              </div>
              <span className="online-dot" />
            </div>

            <div className="sidebar-note">
              <ShieldCheck size={16} />
              <p>
                Requests are monitored by the lab's security detection
                pipeline.
              </p>
            </div>
          </>
        )}

        <div className="sidebar-bottom">
          <div className="user-avatar">
            <UserRound size={17} />
          </div>
          {sidebarOpen && (
            <div className="user-details">
              <span>Lab user</span>
              <small>Persistent session ID</small>
            </div>
          )}
          <span className="online-dot" />
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="topbar-title">
            <span className="mobile-brand-icon">
              <ShieldCheck size={19} />
            </span>
            <div>
              <h1>AI Assistant</h1>
              <p>Private workspace · Security lab</p>
            </div>
          </div>

          <div className={`connection-pill ${apiOnline === false ? 'offline' : apiOnline === true ? 'online' : ''
            }`}>
            {apiOnline === false ? (
              <WifiOff size={14} />
            ) : (
              <Wifi size={14} />
            )}
            <span>
              {apiOnline === false
                ? 'API disconnected'
                : apiOnline === true
                  ? 'API connected'
                  : 'API not tested'}
            </span>
          </div>
        </header>


        <div className="analyst-panel">
          <details>
            <summary> SOC analyst controls</summary>

            <form onSubmit={releaseSession}>
              <label htmlFor="analyst-password">
                Analyst password
              </label>

              <input
                id="analyst-password"
                type="password"
                autoComplete="current-password"
                value={analystPassword}
                onChange={(event) => setAnalystPassword(event.target.value)}
                placeholder="Enter analyst password"
                required
              />

              <button
                type="submit"
                disabled={!analystPassword || releasing}
              >
                {releasing ? 'Releasing…' : 'Release this session'}
              </button>

              {releaseMessage && (
                <p role="status">{releaseMessage}</p>
              )}
            </form>
          </details>
        </div>


        <section className="chat-area">
          <div className="conversation">
            <div className="conversation-heading">
              <div className="heading-icon">
                <Bot size={24} />
              </div>
              <h2>Your AI workspace</h2>
              <p>
                Ask a question to start a conversation. Responses are processed
                by your local FastAPI backend.
              </p>
            </div>

            <div className="message-list" aria-live="polite">
              {messages.map((message) => {
                const details =
                  message.role === 'assistant'
                    ? statusDetails(message.status)
                    : null

                return (
                  <article
                    className={`message-row ${message.role}`}
                    key={message.id}
                  >
                    <div className={`message-avatar ${message.role}`}>
                      {message.role === 'assistant' ? (
                        <Bot size={18} />
                      ) : (
                        <UserRound size={18} />
                      )}
                    </div>

                    <div className="message-content">
                      <div className="message-author">
                        {message.role === 'assistant' ? 'Sentinel AI' : 'You'}
                        {details && (
                          <span className={`status-label ${details.className}`}>
                            <details.Icon size={12} />
                            {details.label}
                          </span>
                        )}
                      </div>

                      <div
                        className={`message-bubble ${details ? `bubble-${details.className}` : ''
                          }`}
                      >
                        {message.text}
                      </div>
                    </div>
                  </article>
                )
              })}

              {loading && (
                <div className="message-row assistant">
                  <div className="message-avatar assistant">
                    <Bot size={18} />
                  </div>
                  <div className="message-content">
                    <div className="message-author">Sentinel AI</div>
                    <div className="typing-bubble">
                      <LoaderCircle size={16} className="spinner" />
                      <span>Processing your message...</span>
                    </div>
                  </div>
                </div>
              )}

              <div ref={bottomRef} />
            </div>
          </div>
        </section>

        <footer className="composer-area">
          <form className="composer" onSubmit={sendMessage}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  sendMessage()
                }
              }}
              placeholder={
                sessionRestricted
                  ? 'Session restricted — contact your SOC analyst.'
                  : 'Message Sentinel AI...'
              }
              aria-label="Message Sentinel AI"
              rows={1}
              disabled={loading || sessionRestricted}
            />
            <button
              className="send-button"
              type="submit"
              disabled={!input.trim() || loading || sessionRestricted}
              aria-label="Send message"
            >
              {loading ? (
                <LoaderCircle size={18} className="spinner" />
              ) : (
                <Send size={17} />
              )}
            </button>
          </form>

          <div className="composer-footer">
            <span>
              <LockKeyhole size={12} />
              Local lab · Requests logged for security monitoring
            </span>
            <span>Enter to send · Shift + Enter for a new line</span>
          </div>
        </footer>
      </main>
    </div>
  )
}

export default App
