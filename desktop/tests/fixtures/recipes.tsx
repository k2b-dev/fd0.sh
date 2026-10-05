import { render } from "solid-js/web";
import { RecipesPanel } from "../../src/renderer/src/features/RecipesPanel";
import type { RecipeView, VaultStatus } from "../../src/shared/contracts";
import "../../src/renderer/src/styles.css";

const script = "set -eu\nvalue=$(cat <&3)\nkubectl -n \"org-k2b-$FD0_TARGET\" apply -f -\n";
const status: VaultStatus = { vaultExists: true, agentRunning: true, unlocked: true, yubikey: false,
  authMethods: [{ id: "pass", type: "passphrase", label: "Passphrase", default: true }] } as VaultStatus;
let approved = new URLSearchParams(location.search).get("approved") !== "0";
const calls: string[] = [];
const view = (): RecipeView => ({
  name: "docs/k8s-1", scope: "kolb-antik-it", scopeId: "s_test", service: "docs",
  command: ["/bin/sh", "-c", script], fields: [{ field: "openai-api-key" }], input: "fd3:file",
  targets: ["fibel", "rsql-docs"], description: "Write the Secret and restart",
  digest: "d".repeat(64), approval: approved ? "approved on this device" : "not approved on this device",
  results: [
    { recipe: "docs/k8s-1", target: "fibel", device: "dev", host: "qdt-dev-1", digest: "", source: "", status: "ok", exitCode: 0, at: "2026-10-05T14:08:00Z" },
    { recipe: "docs/k8s-1", target: "rsql-docs", device: "dev", host: "qdt-dev-1", digest: "", source: "", status: "failed", exitCode: 1, at: "2026-10-05T14:07:00Z" },
  ],
});
Object.defineProperty(window, "fd0", { value: {
  development: true,
  recipeList: async () => ({ recipes: [view()] }),
  recipeApprove: async (input: { name: string; digest: string; passphrase?: string }) => {
    calls.push(`approve:${input.name}:${input.digest.slice(0, 4)}:${input.passphrase ? "auth" : "none"}`);
    approved = true;
    return { recipes: [view()] };
  },
  recipeDeploy: async (input: { name: string; target?: string }) => {
    calls.push(`deploy:${input.name}:${input.target ?? ""}`);
    return { results: [] };
  },
} });
render(() => <div style="max-width:760px;padding:24px"><RecipesPanel scopeId="s_test" service="docs" status={status} /></div>, document.body);
declare global { interface Window { recipeCalls: string[] } }
window.recipeCalls = calls;
