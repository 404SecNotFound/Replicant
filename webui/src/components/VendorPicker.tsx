// Copyright 2026 Imran Hafeez (RZA)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { useId } from "react";
import { Check } from "lucide-react";
import { vendorShortLabel } from "@/lib/api";

interface Props {
  vendor: string;
  vendors: string[];
  onVendorChange: (vendor: string) => void;
  disabled?: boolean;
  reason?: string;
}

export function VendorPicker({ vendor, vendors, onVendorChange, disabled, reason }: Props) {
  const reasonId = useId();
  return (
    <div>
      <div className="u-label mb-2">Firewall profile</div>
      <div role="radiogroup" aria-label="Vendor profile" aria-disabled={disabled || undefined}
        aria-describedby={disabled ? reasonId : undefined} className="flex flex-wrap gap-2">
        {vendors.map((v) => (
          <button key={v} role="radio" aria-checked={vendor === v} disabled={disabled}
            onClick={() => onVendorChange(v)} className="selection-button min-w-fit flex-1 whitespace-nowrap">
            {vendor === v && <Check aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-signal" />}
            {vendorShortLabel(v)}
          </button>
        ))}
      </div>
      {disabled && <p id={reasonId} role="status" className="mt-2 text-label leading-relaxed text-muted-foreground">
        {reason ?? "Vendor profile is locked while a run is active. Stop the active run before switching profiles."}
      </p>}
    </div>
  );
}
