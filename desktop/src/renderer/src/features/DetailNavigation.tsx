import { Show, type JSX } from "solid-js";
import { IconArrowLeft } from "@tabler/icons-solidjs";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";

export function DetailNavigation(props: { narrow: boolean; onShowList(): void }): JSX.Element {
  const vault = useVault();
  const label = () => {
    const item = vault.backItem();
    return item ? `Back to ${item.title}` : "Back to the list";
  };
  return (
    <Show when={vault.backItem() || props.narrow}>
      <div class="detail-back">
        <Button variant="quiet" size="sm" title={label()} onClick={() => vault.backItem() ? vault.goBack() : props.onShowList()}>
          <IconArrowLeft size={17} />
          <span>{label()}</span>
        </Button>
      </div>
    </Show>
  );
}
