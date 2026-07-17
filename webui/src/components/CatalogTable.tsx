import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Technique } from "@/lib/api";

interface Props {
  techniques: Technique[];
  selectedId: string | null;
  onSelect: (t: Technique) => void;
}

export function CatalogTable({ techniques, selectedId, onSelect }: Props) {
  return (
    <Card className="flex min-h-0 flex-1 flex-col">
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Technique catalog</CardTitle>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-y-auto scroll-thin p-0">
        <table className="w-full border-collapse text-sm">
          <thead className="sticky top-0 bg-card">
            <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-4 py-2 font-medium">ID</th>
              <th className="px-2 py-2 font-medium">Technique</th>
              <th className="px-2 py-2 font-medium">UC</th>
              <th className="px-4 py-2 text-right font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {techniques.map((t) => {
              const selected = t.id === selectedId;
              return (
                <tr
                  key={t.id}
                  onClick={() => onSelect(t)}
                  className={cn(
                    "cursor-pointer border-t transition-colors hover:bg-accent/60",
                    selected && "bg-accent",
                  )}
                >
                  <td className="px-4 py-2 font-mono text-xs">{t.id}</td>
                  <td className="px-2 py-2">
                    <div className="font-medium">{t.name}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      {t.log_type}:{t.subtype} · {t.attack.join(", ")}
                    </div>
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-muted-foreground">{t.ndr_uc}</td>
                  <td className="px-4 py-2 text-right">
                    {t.implemented ? (
                      <Badge variant="default">ready</Badge>
                    ) : (
                      <Badge variant="muted">Phase 2</Badge>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
