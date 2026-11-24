import { useState, type FormEvent } from "react";
import {
  decrypt, deriveKey, encrypt, generatePassword, makeSalt, ready, wipe,
  type Entry,
} from "./vault";

type Session = { token: string; key: Uint8Array; version: number; entries: Entry[] };
type RemoteVault = { salt: string; payload: string; version: number };
const blank = (): Entry => ({ id: "", service: "", login: "", password: "" });

async function api<T>(
  path: string, method = "GET", body?: unknown, token?: string,
): Promise<T> {
  const response = await fetch(`/api/${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(
      typeof data.detail === "string" ? data.detail : `Erreur HTTP ${response.status}`,
    );
  }
  return response.json();
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [signup, setSignup] = useState(false);
  const [draft, setDraft] = useState<Entry>(blank);
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setMessage("");
    try { await action(); }
    catch (e) { setMessage(e instanceof Error ? e.message : "Erreur inattendue"); }
    finally { setBusy(false); }
  }

  function authenticate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const username = String(form.get("username"));
    const password = String(form.get("password"));
    const master = String(form.get("master"));
    void run(async () => {
      await ready();
      if (signup) {
        if (master === password) throw new Error("Utilise deux secrets différents.");
        const salt = makeSalt();
        const key = deriveKey(master, salt);
        try {
          await api("register", "POST", {
            username, password, salt, payload: encrypt([], key),
          });
        } finally { wipe(key); }
      }
      const { token } = await api<{ token: string }>("login", "POST", { username, password });
      const remote = await api<RemoteVault>("vault", "GET", undefined, token);
      const key = deriveKey(master, remote.salt);
      try {
        const entries = decrypt(remote.payload, key);
        setSession({ token, key, version: remote.version, entries });
      } catch (e) { wipe(key); throw e; }
    });
  }

  async function save(entries: Entry[]) {
    if (!session) return;
    const { version } = await api<{ version: number }>("vault", "PUT", {
      version: session.version, payload: encrypt(entries, session.key),
    }, session.token);
    setSession({ ...session, entries, version });
    setDraft(blank());
    setMessage("Coffre enregistré.");
  }

  function lock() {
    if (session) wipe(session.key);
    setSession(null);
    setDraft(blank());
    setQuery("");
    setMessage("");
    setSignup(false);
  }

  return (
    <main style={{ maxWidth: 760, margin: "3rem auto", padding: "1rem" }}>
      <h1>Mon coffre-fort</h1>
      <fieldset disabled={busy}>
        {!session ? (
          <form onSubmit={authenticate}>
            <h2>{signup ? "Créer un compte" : "Ouvrir le coffre"}</h2>
            <p><label>Nom du compte <input name="username" required
              pattern="[a-zA-Z0-9_.\-]{3,64}" autoComplete="username" /></label></p>
            <p><label>Mot de passe du compte <input type="password" name="password"
              required minLength={12} maxLength={256}
              autoComplete={signup ? "new-password" : "current-password"} /></label></p>
            <p><label>Phrase maîtresse <input type="password" name="master"
              required minLength={16} autoComplete="off" /></label></p>
            {signup && <p>Choisis une longue phrase unique : elle ne pourra pas être réinitialisée.</p>}
            <button>{signup ? "Créer et ouvrir" : "Ouvrir"}</button>{" "}
            <button type="button" onClick={() => { setSignup(!signup); setMessage(""); }}>
              {signup ? "J’ai déjà un compte" : "Créer un compte"}
            </button>
          </form>
        ) : (
          <>
            <button onClick={lock}>Verrouiller et se déconnecter</button>{" "}
            <button onClick={() => void run(async () => {
              const remote = await api<RemoteVault>("vault", "GET", undefined, session.token);
              setSession({ ...session, entries: decrypt(remote.payload, session.key),
                version: remote.version });
              setDraft(blank());
              setMessage("Dernière version chargée.");
            })}>Recharger et abandonner le brouillon</button>

            <h2>Identifiants · version {session.version}</h2>
            <label>Rechercher <input value={query}
              onChange={e => setQuery(e.target.value)} /></label>
            <ul>
              {session.entries.filter(e =>
                `${e.service} ${e.login}`.toLowerCase().includes(query.toLowerCase()),
              ).map(e => (
                <li key={e.id}>
                  <strong>{e.service}</strong> — {e.login}{" "}
                  <button onClick={() => setDraft({ ...e })}>Modifier</button>{" "}
                  <button onClick={() => {
                    if (window.confirm(`Supprimer l’identifiant pour ${e.service} ?`))
                      void run(() => save(session.entries.filter(x => x.id !== e.id)));
                  }}>Supprimer</button>
                </li>
              ))}
            </ul>

            <h2>{draft.id ? "Modifier un identifiant" : "Nouvel identifiant"}</h2>
            <form onSubmit={e => {
              e.preventDefault();
              const entries = draft.id
                ? session.entries.map(x => x.id === draft.id ? draft : x)
                : [...session.entries, { ...draft, id: crypto.randomUUID() }];
              void run(() => save(entries));
            }}>
              <p><label>Service <input required value={draft.service}
                onChange={e => setDraft({ ...draft, service: e.target.value })} /></label></p>
              <p><label>Identifiant <input required value={draft.login}
                onChange={e => setDraft({ ...draft, login: e.target.value })} /></label></p>
              <p><label>Mot de passe <input required type="password" value={draft.password}
                autoComplete="off"
                onChange={e => setDraft({ ...draft, password: e.target.value })} /></label>{" "}
                <button type="button" onClick={() =>
                  setDraft({ ...draft, password: generatePassword() })}>Générer</button>{" "}
                <button type="button" disabled={!draft.password} onClick={() => void run(async () => {
                  await navigator.clipboard.writeText(draft.password);
                  setMessage("Mot de passe copié dans le presse-papiers du système.");
                })}>Copier</button>
              </p>
              <button>Enregistrer</button>{" "}
              <button type="button" onClick={() => setDraft(blank())}>Annuler</button>
            </form>
          </>
        )}
      </fieldset>
      <p role="status">{busy ? "Opération en cours…" : message}</p>
    </main>
  );
}