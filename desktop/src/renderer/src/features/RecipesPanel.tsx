import { For, Show, createEffect, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
import type { RecipeResult, RecipeView, UnlockInput, VaultStatus } from "../../../shared/contracts";
import { toAppError } from "../lib/errors";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { AuthenticationForm } from "./AuthenticationForm";

function errorText(cause: unknown): string {
  const error = toAppError(cause);
  return error.detail ? `${error.title} ${error.detail}` : error.technical ?? error.title;
}

/** How a recipe receives its values, in words. */
export function inputLabel(input: string): string {
  if (input === "env") return "environment variables";
  const [channel, ...rest] = input.split(":");
  const format = rest.join(":");
  const what = format.startsWith("k8s-secret:") ? `Kubernetes Secret ${format.slice("k8s-secret:".length)}` : format;
  return channel === "fd3" ? `${what} on fd 3` : `${what} on stdin`;
}

function when(at: string): string {
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return at;
  const today = new Date();
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return date.toDateString() === today.toDateString() ? `${time} today` : `${date.toLocaleDateString()} ${time}`;
}

/** The newest result per target, from any device. */
function latestByTarget(results: RecipeResult[]): Map<string, RecipeResult> {
  const latest = new Map<string, RecipeResult>();
  for (const r of results) {
    const current = latest.get(r.target);
    if (!current || r.at > current.at) latest.set(r.target, r);
  }
  return latest;
}

/** argv as a program line plus script blocks for multi-line arguments. */
function CommandBlock(props: { command: string[] }): JSX.Element {
  const head = () => props.command.filter((arg) => !arg.includes("\n")).join(" ");
  const scripts = () => props.command.filter((arg) => arg.includes("\n"));
  return <div class="recipe-command">
    <div class="recipe-command-head"><span>Command</span><code>{head()}</code></div>
    <For each={scripts()}>{(script) => <pre class="recipe-code">
      <For each={script.replace(/\n$/, "").split("\n")}>{(line) => <span>{line}</span>}</For>
    </pre>}</For>
  </div>;
}

export function RecipesPanel(props: { scopeId: string; service: string; status: VaultStatus | null }): JSX.Element {
  const [recipes, setRecipes] = createSignal<RecipeView[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal("");
  const [reviewing, setReviewing] = createSignal<RecipeView>();
  const [confirming, setConfirming] = createSignal<{ name: string; target?: string; label: string }>();
  let alive = true;
  let revision = 0;
  onCleanup(() => { alive = false; revision++; });

  async function refresh(): Promise<void> {
    const current = ++revision;
    try {
      const result = await window.fd0.recipeList(props.scopeId, props.service);
      if (alive && current === revision) { setRecipes(result.recipes); setError(""); }
    } catch (cause) {
      if (alive && current === revision) setError(errorText(cause));
    } finally {
      if (alive && current === revision) setLoaded(true);
    }
  }
  createEffect(() => { props.scopeId; props.service; setLoaded(false); void refresh(); });

  const allApproved = createMemo(() => recipes().length > 0 && recipes().every((r) => r.approval === "approved on this device"));

  async function approve(input: UnlockInput): Promise<void> {
    const r = reviewing();
    if (!r) return;
    const result = await window.fd0.recipeApprove({ ...input, scopeId: r.scopeId, name: r.name, digest: r.digest });
    if (!alive) return;
    setRecipes(result.recipes);
    setReviewing(undefined);
  }

  async function deploy(name: string, target?: string): Promise<void> {
    setConfirming(undefined);
    setBusy(target ? `${name}\u0000${target}` : name);
    setError("");
    try {
      const result = await window.fd0.recipeDeploy({ scopeId: props.scopeId, name, target });
      if (alive && result.error) setError(result.error);
    } catch (cause) {
      if (alive) setError(errorText(cause));
    } finally {
      if (alive) { setBusy(""); await refresh(); }
    }
  }

  return <Show when={loaded() && (recipes().length > 0 || error())}>
    <section class="field-section recipes-panel" aria-label="Deploys">
      <div class="recipes-heading">
        <h2 class="section-heading">Deploys</h2>
        <Show when={recipes().length > 1}>
          <Button size="sm" disabled={!allApproved() || busy() !== ""}
            onClick={() => setConfirming({ name: props.service, label: `all ${recipes().length} recipes of ${props.service}` })}>
            Deploy all
          </Button>
        </Show>
      </div>
      <For each={recipes()}>{(r) => {
        const approved = () => r.approval === "approved on this device";
        const targets = () => (r.targets?.length ? r.targets : [""]);
        const latest = () => latestByTarget(r.results);
        const running = (target?: string) => busy() === r.name || busy() === r.service || (target !== undefined && busy() === `${r.name}\u0000${target}`);
        return <article class="recipe-card" aria-label={`Recipe ${r.name}`}>
          <header class="recipe-card-head">
            <div class="recipe-card-title">
              <strong>{r.name.slice(r.service.length + 1)}</strong>
              <Show when={r.description}><small>{r.description}</small></Show>
            </div>
            <Show when={approved()} fallback={<Button size="sm" onClick={() => setReviewing(r)}>Approve…</Button>}>
              <Button size="sm" disabled={busy() !== ""}
                onClick={() => setConfirming({ name: r.name, label: `${r.name} to ${targets().filter(Boolean).length || 1} target${targets().length === 1 ? "" : "s"}` })}>
                {running() ? "Deploying…" : "Deploy"}
              </Button>
            </Show>
          </header>
          <Show when={!approved()}>
            <p class="recipe-note">{r.approval === "changed since approval on this device" ? "Changed since you approved it on this device. Review it again before it can run here." : "Not approved on this device. Review it before it can run here."}</p>
          </Show>
          <p class="recipe-receives">Receives <span>{r.fields.map((f) => f.as ? `${f.field} as ${f.as}` : f.field).join(", ")}</span> · {inputLabel(r.input)}</p>
          <table class="recipe-targets">
            <tbody>
              <For each={targets()}>{(t) => {
                const result = () => latest().get(t);
                return <tr>
                  <th scope="row">{t || "Single run"}</th>
                  <td>
                    <Show when={!running(t)} fallback={<span>Running…</span>}>
                      <Show when={result()} fallback={<span class="recipe-muted">Not deployed yet</span>}>
                        {(res) => <>
                          <Show when={res().status !== "ok"}><span class="recipe-failed">Failed · exit {res().exitCode}</span><span class="recipe-muted"> · </span></Show>
                          <span class="recipe-muted">{when(res().at)} · {res().host}</span>
                        </>}
                      </Show>
                    </Show>
                  </td>
                  <td class="recipe-target-action">
                    <Show when={approved() && t}>
                      <Button size="sm" variant="quiet" disabled={busy() !== ""} aria-label={`Deploy ${r.name} to ${t}`}
                        onClick={() => setConfirming({ name: r.name, target: t, label: `${r.name} to ${t}` })}>Deploy</Button>
                    </Show>
                  </td>
                </tr>;
              }}</For>
            </tbody>
          </table>
          <CommandBlock command={r.command} />
        </article>;
      }}</For>
      <Show when={error()}><p role="alert" class="recipe-error">{error()}</p></Show>

      <Show when={confirming()}>{(c) => <Modal size="small" title="Deploy now?" description={`fd0 syncs, then runs ${c().label} on this device. It stops at the first failure.`}
        onClose={() => setConfirming(undefined)}
        footer={<><Button variant="quiet" onClick={() => setConfirming(undefined)}>Cancel</Button><Button variant="primary" onClick={() => void deploy(c().name, c().target)}>Deploy</Button></>}>
        <p class="recipe-muted">The commands run as your user with the selected values. Their output stays hidden because it can contain values.</p>
      </Modal>}</Show>

      <Show when={reviewing()}>{(r) => <Modal size="wide" title={`Approve ${r().name}`} description={`${r().scope}`} onClose={() => setReviewing(undefined)}>
        <dl class="recipe-review">
          <dt>Receives</dt><dd>{r().fields.map((f) => f.as ? `${f.field} as ${f.as}` : f.field).join(", ")} · {inputLabel(r().input)}</dd>
          <Show when={r().targets?.length}><dt>Targets</dt><dd>{r().targets!.join(", ")} · once each, as $FD0_TARGET</dd></Show>
          <Show when={r().dir}><dt>Directory</dt><dd><code>{r().dir}</code></dd></Show>
        </dl>
        <CommandBlock command={r().command} />
        <p class="recipe-warning">This device will run exactly this command as your user, with the selected values, when you deploy. fd0 does not check the scripts or tool settings it calls. Any change to the recipe needs a new approval.</p>
        <AuthenticationForm status={props.status} submitLabel="Approve on this device" pendingLabel="Approving…"
          onAuthenticate={approve} onCancel={() => setReviewing(undefined)} />
      </Modal>}</Show>
    </section>
  </Show>;
}
