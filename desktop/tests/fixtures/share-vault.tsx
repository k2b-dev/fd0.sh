import { render } from "solid-js/web";
import { ShareVaultModal } from "../../src/renderer/src/components/ShareVaultModal";
import type { ScopeRole, ScopeShareInfo } from "../../src/shared/contracts";
import "../../src/renderer/src/styles.css";

const params = new URLSearchParams(location.search);
const selfRole = (params.get("role") ?? "admin") as ScopeRole;
const calls: string[] = [];
const info: ScopeShareInfo = {
  scopeLabel: "ci-deploy",
  selfRole,
  contacts: [{ label: "Benny", fingerprint: "abc", shared: false }],
  members: [
    { id: "self", label: "You", fingerprint: "s", self: true, trusted: true, role: selfRole },
    { id: "runner", label: "ci-runner", fingerprint: "r", trusted: true, role: "reader" },
  ],
};
Object.defineProperty(window, "fd0", { value: {
  development: true,
  scopeShareInfo: async () => info,
  addScopeMember: async (_scope: string, label: string, role: string) => { calls.push(`add:${label}:${role}`); return { ok: true }; },
  setScopeMemberRole: async (_scope: string, member: string, role: string) => { calls.push(`role:${member}:${role}`); return { ok: true }; },
  removeScopeMember: async () => ({ ok: true }),
} });
render(() => <ShareVaultModal scope={{ id: "s_test", label: "ci-deploy" } as never} onClose={() => {}} onChanged={async () => {}} onNotify={() => {}} />, document.body);
declare global { interface Window { shareCalls: string[] } }
window.shareCalls = calls;
