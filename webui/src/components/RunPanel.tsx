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

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Check, ChevronRight, Play, Square } from "lucide-react";
import { TechniquePreview } from "@/components/TechniquePreview";
import { Input } from "@/components/ui/input";
import { CefLine } from "@/components/CefLine";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SignalReadout } from "@/components/SignalReadout";
import { cn } from "@/lib/utils";
import {
  ApiError,
  getActiveRun,
  getPlanPreview,
  getRunAdmission,
  getRunStatus,
  reserveRun,
  runEventsUrl,
  startRun,
  stopRun,
  vendorShortLabel,
  type ActiveRun,
  type Collector,
  type Manifest,
  type RunBody,
  type RunAdmissionState,
  type Technique,
} from "@/lib/api";
import { isTerminalStatus, pollRunUntilTerminal } from "@/lib/runLifecycle";
import { anchorNotice, defaultAnchor, type AnchorChoice } from "@/lib/anchor";
import {
  defaultPace,
  fmtSpan,
  paceConsequence,
  projectedFor,
  type PaceChoice,
  type PlanPreview,
} from "@/lib/pacing";

export interface RunAdmission {
  technique_id: string;
  vendor: string;
}

interface Props {
  vendorControls?: ReactNode;
  onChooseTechnique?: () => void;
  onConfigureCollector?: () => void;
  technique: Technique | null;
  defaultSeed: number;
  collector: Collector | null;
  vendor: string;
  epsCap: number;
  anchorEpoch: number;
  /** Owner already established by App's bootstrap probe, if any. */
  initialActiveRun?: ActiveRun | null;
  onActiveRunChange?: (activeRun: ActiveRun | null) => void;
  onActiveRunDiscoveryChange?: (pending: boolean) => void;
  onRunAdmissionChange?: (admission: RunAdmission | null) => void;
}

const MAX_VISIBLE = 800;
const SAMPLE_MS = 220;
// Number of plotted samples. Exported alongside SAMPLE_MS so the readout can
// label the real window instead of a hardcoded guess.
const SAMPLE_WINDOW = 48;
const ACTIVE_RUN_POLL_MS = 1000;
// Per-send spacing is intentionally smooth, but browser callbacks and rendering
// samples still have scheduling jitter. A rolling second keeps that jitter from
// making a steady run flicker between misleading instantaneous rates.
const RATE_WINDOW_MS = 1000;

function createAdmissionId(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) throw new Error("Web Crypto is unavailable");
  if (typeof cryptoApi.randomUUID === "function") return cryptoApi.randomUUID();

  // randomUUID requires a secure context in some browsers. getRandomValues is
  // also cryptographically strong and remains available to an HTTP client on a
  // private lab segment, which is a supported Replicant deployment.
  const bytes = cryptoApi.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10).join(""),
  ].join("-");
}

function fmtDur(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`;
}

export function RunPanel({
  vendorControls,
  onChooseTechnique,
  onConfigureCollector,
  technique,
  defaultSeed,
  collector,
  vendor,
  epsCap,
  anchorEpoch,
  initialActiveRun,
  onActiveRunChange,
  onActiveRunDiscoveryChange,
  onRunAdmissionChange,
}: Props) {
  const bootstrapOwner = initialActiveRun?.run_id ? initialActiveRun : null;
  const [intensity, setIntensity] = useState("medium");
  const [signatureMode, setSignatureMode] = useState<"mixed" | "single">("mixed");
  const [duration, setDuration] = useState("");
  const [seed, setSeed] = useState(String(defaultSeed));
  // null means the operator has not decided, which follows the collector: one
  // that is configured and verified is a statement of intent, and it is the same
  // statement `replicant run REP-001 --host ...` makes on the CLI, where sending
  // is the default and `--no-send` is the opt-out. This form defaulted the other
  // way, so a verified collector plus a technique plus the run button produced a
  // run that rendered every event and delivered none. An explicit toggle wins and
  // survives a reconnect, so turning it off is not undone by the collector panel.
  const [sendChoice, setSendChoice] = useState<boolean | null>(null);
  const sendToCollector = sendChoice ?? collector !== null;
  const [toFile, setToFile] = useState(false);
  const [filePath, setFilePath] = useState("replicant.log");
  const [anchor, setAnchor] = useState<AnchorChoice>(defaultAnchor(false));
  // Events per second, blank meaning the configured cap. Exposed because the
  // default is a ceiling suited to protecting a collector from a flood, not a
  // rate every collector can ingest, and a live LogRhythm test lost an entire
  // run to that difference with no way to turn it down from this form.
  const [rate, setRate] = useState("");
  // How the plan's own timeline reaches the wire, and how much it is compressed.
  // Unset until the destination is known, then defaulted from it, the same way
  // the anchor control follows the destination.
  const [pace, setPace] = useState<PaceChoice>(defaultPace(false));
  const [speed, setSpeed] = useState("1");
  const [preview, setPreview] = useState<PlanPreview | null>(null);
  const [previewPending, setPreviewPending] = useState(false);

  const [runDraft, setRunDraft] = useState<{ body: RunBody; name: string; outputPath?: string | null } | null>(null);

  const [starting, setStarting] = useState(false);
  const [running, setRunning] = useState(false);
  // The run holding the server's single-run lock, when it is not this panel's.
  //
  // Only one run may be active, because each carries its own rate limiter and
  // two against one collector would multiply the eps cap (safety rule 4). But
  // `running` above is per-panel state: selecting a different technique remounts
  // this component, the flag resets, the button re-enables, and the start then
  // fails with a 409 naming a run the operator cannot see. Asking the server on
  // mount is the only way to know, because the server is the only thing that
  // does.
  const [lockedBy, setLockedBy] = useState<ActiveRun | null>(() => bootstrapOwner);
  // A stop request is not terminal state. Keep the external run as the active
  // vendor lock until its status endpoint confirms done, stopped, or error.
  const [stoppingLockedRunId, setStoppingLockedRunId] = useState<string | null>(null);
  // Do not report an empty owner to App while the initial authoritative probe
  // is still pending; App may already hold bootstrap identity for a restored run.
  const [lockProbeComplete, setLockProbeComplete] = useState(() => bootstrapOwner !== null);
  const [count, setCount] = useState(0);
  const [total, setTotal] = useState(0);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [manifestOwnerId, setManifestOwnerId] = useState<string | null>(null);
  // Whether the run in flight is actually being throttled. Frozen when the run
  // starts rather than read live from the form, so toggling the destination
  // mid-run cannot relabel a run that is already emitting.
  const [runSending, setRunSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [eps, setEps] = useState(0);
  const [samples, setSamples] = useState<number[]>([]);
  const [elapsed, setElapsed] = useState("0s");

  const linesRef = useRef<string[]>([]);
  const esRef = useRef<EventSource | null>(null);
  const runIdRef = useRef<string | null>(null);
  const runTechniqueRef = useRef<string | null>(null);
  const runVendorRef = useRef<string | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);
  const countRef = useRef(0);
  const startRef = useRef(0);
  const mountedRef = useRef(true);
  // Mirror the state initializer. App's bootstrap result is authoritative even
  // if this panel's duplicate discovery probe fails, so its watcher must start
  // with the same owner and retain it through that transient failure.
  const lockedByRef = useRef<ActiveRun | null>(bootstrapOwner);
  const stoppingLockedRunIdRef = useRef<string | null>(null);
  // refreshLock and terminal ownership confirmation can overlap. Only the most
  // recently started active-owner probe may publish its result.
  const activeProbeGenerationRef = useRef(0);
  // A start response can outlive this component or a newer attempt. Only the
  // latest mounted attempt may adopt the returned run or attach an EventSource.
  const startAttemptGenerationRef = useRef(0);
  // State disables the rendered button; this ref closes the same-tick window
  // before React commits that render.
  const startPendingRef = useRef(false);
  const admissionRetryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const finishAdmissionRetryRef = useRef<(() => void) | null>(null);
  // Trailing observations of (timestamp, cumulative count), used to average the
  // emission rate over RATE_WINDOW_MS instead of over a single 220ms tick.
  const historyRef = useRef<{ t: number; c: number }[]>([]);

  // Declare the mounted lifecycle before effects that start probes/watchers.
  // StrictMode replays effect setup after cleanup in declaration order, so the
  // guard must be restored before those later effects consult it.
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      activeProbeGenerationRef.current += 1;
      startAttemptGenerationRef.current += 1;
      // Do not erase authoritative refs here. React StrictMode runs effect
      // setup, cleanup, then setup again while preserving state; clearing only
      // the refs would split them from `lockedBy` and strand its watcher. The
      // mounted/generation guards above still make real-unmount continuations
      // inert.
      if (admissionRetryTimerRef.current !== null) {
        clearTimeout(admissionRetryTimerRef.current);
      }
      finishAdmissionRetryRef.current?.();
      esRef.current?.close();
    };
  }, []);

  const commitLockedBy = useCallback((next: ActiveRun | null) => {
    const stoppingRunId = stoppingLockedRunIdRef.current;
    if (stoppingRunId && stoppingRunId !== next?.run_id) {
      stoppingLockedRunIdRef.current = null;
      setStoppingLockedRunId(null);
    }
    lockedByRef.current = next;
    setLockedBy(next);
  }, []);

  const updateLockedBy = useCallback((runId: string, patch: Partial<ActiveRun>) => {
    const current = lockedByRef.current;
    if (current?.run_id !== runId) return;
    const next = { ...current, ...patch };
    lockedByRef.current = next;
    setLockedBy(next);
  }, []);

  const probeActiveOwner = useCallback(async () => {
    const generation = ++activeProbeGenerationRef.current;
    try {
      const active = await getActiveRun();
      if (!mountedRef.current || generation !== activeProbeGenerationRef.current) {
        return { kind: "stale" } as const;
      }
      return { kind: "current", active } as const;
    } catch {
      if (!mountedRef.current || generation !== activeProbeGenerationRef.current) {
        return { kind: "stale" } as const;
      }
      return { kind: "error" } as const;
    }
  }, []);

  // A local terminal notification says A stopped emitting. It does not say who
  // owns the server lock now: B can start after the backend marks A terminal but
  // before this browser receives A's final SSE item. Move A into the same
  // ownership-confirmation state used by restored runs before clearing
  // `running`, so the parent can transfer A directly to B without seeing null.
  const holdLocalTerminalUntilOwnerConfirmed = useCallback(
    (runId: string, status: string, eventCount: number, runTotal: number) => {
      if (!mountedRef.current || runIdRef.current !== runId) return;
      const knownOwner = lockedByRef.current;
      if (!knownOwner?.run_id || knownOwner.run_id === runId) {
        commitLockedBy({
          run_id: runId,
          technique_id: runTechniqueRef.current,
          vendor: runVendorRef.current,
          status,
          event_count: eventCount,
          total: runTotal,
        });
      }
      setRunning(false);
    },
    [commitLockedBy],
  );

  // Ask the server what is running, on mount and whenever the technique changes,
  // which is exactly when this component's own state has just been thrown away.
  const refreshLock = useCallback(async (): Promise<boolean> => {
    // Admission owns reconciliation through its exact server-side identity.
    // Do not launch a competing general owner probe while that protocol runs.
    if (startPendingRef.current) return false;
    const expectedOwnerId = lockedByRef.current?.run_id ?? null;
    const result = await probeActiveOwner();
    // Errors and superseded probes deliberately retain the known owner.
    if (result.kind !== "current") return false;
    // Technique selection can launch a new refresh while POST /runs is pending.
    // Its snapshot cannot settle that newer admission or publish a competing
    // owner. The accepted response or uncertainty reconciliation owns that job.
    if (startPendingRef.current) return false;
    setLockProbeComplete(true);
    // Another probe or terminal handoff has already installed a newer owner.
    // This response describes the older state and must not overwrite it.
    if ((lockedByRef.current?.run_id ?? null) !== expectedOwnerId) return true;
    const active = result.active;
    if (active.run_id && active.run_id === expectedOwnerId) {
      // The active endpoint has confirmed identity, which we already know.
      // Its snapshot may predate a newer status poll, so never let it regress
      // terminal state or the monotonic event count owned by that watcher.
      onRunAdmissionChange?.(null);
      return true;
    }
    const mine = active.run_id !== null && active.run_id === runIdRef.current;
    if (active.run_id && !mine) {
      // This is also the safe A-to-B transfer path: never clear A first and
      // briefly tell the parent there is no lock.
      onActiveRunChange?.(active);
      onRunAdmissionChange?.(null);
      commitLockedBy(active);
    } else if (!lockedByRef.current?.run_id) {
      // This also clears admission left behind when a pending RunPanel unmounted.
      // A current no-owner probe is the authority that no accepted run remains.
      onRunAdmissionChange?.(null);
      commitLockedBy(null);
    }
    return true;
  }, [commitLockedBy, onActiveRunChange, onRunAdmissionChange, probeActiveOwner]);

  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    const refreshUntilKnown = async () => {
      const complete = await refreshLock();
      if (!cancelled && !complete) {
        retryTimer = setTimeout(() => void refreshUntilKnown(), ACTIVE_RUN_POLL_MS);
      }
    };

    void refreshUntilKnown();
    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
    };
  }, [refreshLock, technique]);

  // Every server-discovered run gets exactly one watcher, whether the operator
  // presses Stop or simply waits for natural completion. Depending only on the
  // run id prevents progress refreshes and technique changes from spawning
  // duplicate loops. Changing ids or unmounting cancels the old loop.
  useEffect(() => {
    const runId = lockedBy?.run_id;
    if (!runId) return;
    let cancelled = false;
    let sleepTimer: ReturnType<typeof setTimeout> | null = null;
    let finishSleep: (() => void) | null = null;
    const sleep = (ms: number) =>
      new Promise<void>((resolve) => {
        if (cancelled) {
          resolve();
          return;
        }
        finishSleep = () => {
          sleepTimer = null;
          finishSleep = null;
          resolve();
        };
        sleepTimer = setTimeout(finishSleep, ms);
      });

    async function confirmActiveOwner(): Promise<void> {
      while (!cancelled && mountedRef.current) {
        if (lockedByRef.current?.run_id !== runId) return;
        const result = await probeActiveOwner();
        if (result.kind !== "current") {
          await sleep(ACTIVE_RUN_POLL_MS);
          continue;
        }
        if (cancelled || !mountedRef.current) return;
        // A newer refresh or ownership probe already transferred the lock.
        // Never let this older A response clear or replace that successor.
        if (lockedByRef.current?.run_id !== runId) return;
        const active = result.active;

        // The status endpoint can become terminal just before RunManager clears
        // its active pointer. Keep A locked until that handoff is authoritative.
        if (active.run_id === runId) {
          await sleep(ACTIVE_RUN_POLL_MS);
          continue;
        }

        // Any different non-null id is the new owner. Do not discard it merely
        // because this panel remembers that id from an older local run.
        commitLockedBy(active.run_id ? active : null);
        return;
      }
    }

    const current = lockedByRef.current;
    if (current?.run_id === runId && current.status && isTerminalStatus(current.status)) {
      void confirmActiveOwner();
    } else {
      void pollRunUntilTerminal({
        getStatus: async () => {
          const snapshot = await getRunStatus(runId);
          if (!cancelled && mountedRef.current) {
            updateLockedBy(runId, {
              admission_id: snapshot.admission_id,
              vendor: snapshot.vendor,
              status: snapshot.status,
              event_count: snapshot.event_count,
              total: snapshot.total,
            });
          }
          return snapshot;
        },
        onProgress: (eventCount) => {
          if (cancelled || !mountedRef.current) return;
          updateLockedBy(runId, { event_count: eventCount });
        },
        onTerminal: (snapshot) => {
          if (cancelled || !mountedRef.current) return;
          updateLockedBy(runId, {
            status: snapshot.status,
            event_count: snapshot.event_count,
          });
          if (snapshot.manifest) { setManifest(snapshot.manifest as Manifest); setManifestOwnerId(runId); }
          void confirmActiveOwner();
        },
        sleep,
        isCancelled: () => cancelled || !mountedRef.current,
        onFetchError: (statusError) => {
          if (statusError instanceof ApiError && statusError.status === 404) {
            // The bounded status history can evict A before this restored view
            // observes its terminal snapshot. Stop asking for A and reconcile
            // against the authoritative active pointer while retaining A's lock.
            void confirmActiveOwner();
            return "stop";
          }
          return "retry";
        },
        intervalMs: ACTIVE_RUN_POLL_MS,
      });
    }

    return () => {
      cancelled = true;
      if (sleepTimer !== null) clearTimeout(sleepTimer);
      finishSleep?.();
    };
  }, [commitLockedBy, lockedBy?.run_id, probeActiveOwner, updateLockedBy]);

  // The vendor picker lives above this component, but this component owns the
  // authoritative local/remote run state. Report only that small piece upward
  // so switching profiles cannot unmount an in-flight panel and relabel its
  // stream. The technique is frozen at start because browsing the catalog does
  // not change which technique the already-running worker is executing.
  useEffect(() => {
    if (!onActiveRunChange) return;
    if (lockedBy?.run_id) {
      onActiveRunChange(lockedBy);
    } else if (running && runIdRef.current) {
      onActiveRunChange({
        run_id: runIdRef.current,
        technique_id: runTechniqueRef.current,
        vendor: runVendorRef.current,
        status: "running",
      });
    } else if (lockProbeComplete) {
      onActiveRunChange(null);
    }
  }, [lockProbeComplete, lockedBy, onActiveRunChange, running]);

  useEffect(() => {
    onActiveRunDiscoveryChange?.(!lockProbeComplete);
  }, [lockProbeComplete, onActiveRunDiscoveryChange]);

  useEffect(() => setSeed(String(defaultSeed)), [defaultSeed]);
  useEffect(() => {
    if (technique && !technique.intensities.includes(intensity)) {
      setIntensity(technique.intensities.includes("medium") ? "medium" : technique.intensities[0]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [technique]);
  useEffect(() => {
    // Losing the collector clears the explicit choice rather than forcing it off,
    // so the switch follows the next collector instead of staying stuck on a
    // decision made about a destination that no longer exists. Same reasoning as
    // the anchor reset below.
    if (collector === null) setSendChoice(null);
  }, [collector]);

  // Whether a run started right now would go to a collector. Drives both the
  // anchor default and whether the eps cap is in force.
  const sending = sendToCollector && collector !== null;

  // Follow the destination. Changing where the events go changes which anchor is
  // correct, so the control resets to the right default for the new destination
  // rather than silently carrying the previous choice into a run where it is wrong.
  useEffect(() => {
    setAnchor(defaultAnchor(sending));
  }, [sending]);

  // Same rule for the pace. A collector is the only place the delivered shape
  // matters, and a file has no wall clock to reproduce, so the destination picks
  // the default rather than the operator having to know the option exists.
  useEffect(() => {
    setPace(defaultPace(sending));
  }, [sending]);

  const speedNum = Math.max(1, Number(speed) || 1);
  const requestedRate = rate.trim() ? Number(rate.trim()) : null;
  const rateError =
    requestedRate !== null && requestedRate > epsCap
      ? `${requestedRate} events/s exceeds the configured cap of ${epsCap} events/s. A per-run rate may lower this safety ceiling, not raise it.`
      : null;
  // Burst has no timeline to compress. The server refuses that combination
  // rather than ignoring it, so the form never sends one it already knows is
  // contradictory.
  const effectiveSpeed = pace === "plan" ? speedNum : 1;

  function buildBody(): RunBody | null {
    if (!technique || rateError) return null;
    return {
      technique_id: technique.id,
      intensity,
      duration: duration.trim() || null,
      seed: Number(seed),
      to_file: toFile ? filePath : null,
      no_send: !(sendToCollector && collector),
      collector: sendToCollector ? collector : null,
      vendor,
      anchor,
      // Blank means the configured cap. Sent as a number so the server's
      // gt=0 constraint rejects nonsense rather than silently flooding.
      rate: requestedRate,
      pace,
      speed: effectiveSpeed,
      signature_mode: technique.id === "REP-009" ? signatureMode : null,
    };
  }

  // Price the run before it starts, using the same body the run itself will use
  // so the two cannot describe different runs. Debounced because the server has
  // to build the plan to answer, and REP-004 at high intensity is 180,000 events.
  useEffect(() => {
    const body = buildBody();
    if (!body) {
      setPreview(null);
      setPreviewPending(false);
      return;
    }
    setPreviewPending(true);
    setPreview(null);
    let cancelled = false;
    const timer = setTimeout(() => {
      getPlanPreview(body)
        .then((next) => {
          if (!cancelled) { setPreview(next); setPreviewPending(false); }
        })
        .catch(() => {
          // A failed preview leaves the control describing the shape of the
          // answer without inventing numbers for it.
          if (!cancelled) { setPreview(null); setPreviewPending(false); }
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    technique,
    intensity,
    duration,
    seed,
    anchor,
    rate,
    pace,
    effectiveSpeed,
    sending,
    toFile,
    filePath,
  ]);

  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      const now = performance.now();
      const history = historyRef.current;
      history.push({ t: now, c: countRef.current });

      // Drop observations older than the rate window, but always keep the one
      // immediately preceding it so the window stays a full RATE_WINDOW_MS wide
      // rather than collapsing toward the newest sample.
      const cutoff = now - RATE_WINDOW_MS;
      let firstFresh = 0;
      while (firstFresh < history.length && history[firstFresh].t < cutoff) firstFresh++;
      if (firstFresh > 0) history.splice(0, firstFresh - 1);

      const oldest = history[0];
      const dt = (now - oldest.t) / 1000;
      if (dt > 0) {
        const rate = Math.max(0, (countRef.current - oldest.c) / dt);
        setEps(Math.round(rate));
        setSamples((s) => [...s.slice(-(SAMPLE_WINDOW - 1)), rate]);
      }
      setElapsed(fmtDur((now - startRef.current) / 1000));
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, SAMPLE_MS);
    return () => clearInterval(timer);
  }, [running]);

  function reset() {
    linesRef.current = [];
    setCount(0);
    setTotal(0);
    setManifest(null);
    setManifestOwnerId(null);
    setError(null);
    setEps(0);
    setSamples([]);
    setElapsed("0s");
    countRef.current = 0;
    startRef.current = performance.now();
    historyRef.current = [{ t: performance.now(), c: 0 }];
  }

  function waitForAdmissionRetry(): Promise<void> {
    return new Promise((resolve) => {
      const finish = () => {
        if (finishAdmissionRetryRef.current !== finish) return;
        admissionRetryTimerRef.current = null;
        finishAdmissionRetryRef.current = null;
        resolve();
      };
      finishAdmissionRetryRef.current = finish;
      admissionRetryTimerRef.current = setTimeout(finish, ACTIVE_RUN_POLL_MS);
    });
  }

  const attemptIsCurrent = (attempt: number) =>
    mountedRef.current
    && attempt === startAttemptGenerationRef.current
    && startPendingRef.current;

  function settleAdmissionWithOwner(owner: ActiveRun, message: string): void {
    activeProbeGenerationRef.current += 1;
    startPendingRef.current = false;
    setStarting(false);
    setRunning(false);
    setLockProbeComplete(true);
    setError(message);
    onActiveRunChange?.(owner);
    onRunAdmissionChange?.(null);
    commitLockedBy(owner);
  }

  function settleAdmissionWithoutOwner(message: string): void {
    activeProbeGenerationRef.current += 1;
    startPendingRef.current = false;
    setStarting(false);
    setRunning(false);
    setLockProbeComplete(true);
    setError(message);
    onActiveRunChange?.(null);
    onRunAdmissionChange?.(null);
    commitLockedBy(null);
  }

  function ownerFromAdmission(admission: RunAdmissionState): ActiveRun {
    return {
      admission_id: admission.admission_id,
      run_id: admission.run_id,
      technique_id: admission.technique_id,
      vendor: admission.vendor,
      status: admission.status,
      event_count: admission.event_count,
      total: admission.total,
    };
  }

  async function reconcileCurrentOwnerAfterAdmission(
    attempt: number,
    noOwnerMessage: string,
  ): Promise<void> {
    while (attemptIsCurrent(attempt)) {
      const result = await probeActiveOwner();
      if (!attemptIsCurrent(attempt)) return;
      if (result.kind !== "current") {
        await waitForAdmissionRetry();
        continue;
      }
      if (result.active.run_id) {
        settleAdmissionWithOwner(
          result.active,
          `The admission ended, and ${result.active.technique_id ?? "the active run"} now owns the server.`,
        );
      } else {
        settleAdmissionWithoutOwner(noOwnerMessage);
      }
      return;
    }
  }

  async function reserveAdmissionWithRetry(
    attempt: number,
    admissionId: string,
    techniqueId: string,
    requestedVendor: string,
  ): Promise<RunAdmissionState | null> {
    while (attemptIsCurrent(attempt)) {
      try {
        const reservation = await reserveRun({
          admission_id: admissionId,
          technique_id: techniqueId,
          vendor: requestedVendor,
        });
        return attemptIsCurrent(attempt) ? reservation : null;
      } catch (reserveError) {
        if (
          reserveError instanceof ApiError
          && reserveError.status >= 400
          && reserveError.status < 500
        ) {
          throw reserveError;
        }
        // Retrying the same browser-generated id is safe whether the first
        // request never arrived or only its response was lost.
        setError(
          `admission reservation response unavailable; retrying the same identity: ${(reserveError as Error).message}`,
        );
        await waitForAdmissionRetry();
      }
    }
    return null;
  }

  async function reconcileUncertainStart(
    attempt: number,
    reservation: RunAdmissionState,
    failureMessage: string,
  ): Promise<void> {
    let cancellationAcknowledged = false;
    while (attemptIsCurrent(attempt)) {
      let admission: RunAdmissionState;
      try {
        admission = await getRunAdmission(reservation.admission_id);
      } catch (statusError) {
        if (!attemptIsCurrent(attempt)) return;
        if (statusError instanceof ApiError && statusError.status === 404) {
          // A restart or bounded-history eviction can remove the exact record.
          // The current active pointer is then the remaining authority.
          await reconcileCurrentOwnerAfterAdmission(
            attempt,
            `start failed: ${failureMessage}`,
          );
          return;
        }
        if (
          statusError instanceof ApiError
          && statusError.status >= 400
          && statusError.status < 500
        ) {
          // The reservation is known to exist, but this browser can no longer
          // inspect or cancel it. Convert pending admission into a known owner so
          // navigation is available while the vendor and Run controls stay safe.
          settleAdmissionWithOwner(
            ownerFromAdmission(reservation),
            `Admission status is unavailable because this browser session is no longer authorized. Reopen the URL printed by replicant web to inspect or cancel ${reservation.technique_id}.`,
          );
          return;
        }
        await waitForAdmissionRetry();
        continue;
      }

      if (!attemptIsCurrent(attempt)) return;
      if (admission.status === "running") {
        settleAdmissionWithOwner(
          ownerFromAdmission(admission),
          `The start response was unavailable, but ${admission.technique_id} was recovered from its admission record.`,
        );
        return;
      }
      if (admission.status === "admitting") {
        setError(
          `start response unavailable; the server is still preparing ${admission.technique_id} under its reserved identity.`,
        );
        await waitForAdmissionRetry();
        continue;
      }
      if (admission.status === "reserved" && !cancellationAcknowledged) {
        // The ambiguous POST has not claimed the reservation. Atomically cancel
        // it so a delayed copy cannot start after the UI unlocks.
        try {
          const cancelled = await stopRun(admission.run_id);
          if (!attemptIsCurrent(attempt)) return;
          if (!cancelled.ok) {
            await reconcileCurrentOwnerAfterAdmission(
              attempt,
              `start failed: ${failureMessage}`,
            );
            return;
          }
          cancellationAcknowledged = true;
          setError("the unclaimed run reservation was cancelled; confirming current ownership.");
        } catch (cancelError) {
          if (!attemptIsCurrent(attempt)) return;
          if (
            cancelError instanceof ApiError
            && cancelError.status >= 400
            && cancelError.status < 500
          ) {
            settleAdmissionWithOwner(
              ownerFromAdmission(admission),
              `The rejected start left a reserved owner that this browser can no longer cancel. Reopen the URL printed by replicant web to inspect or cancel ${admission.technique_id}.`,
            );
            return;
          }
          await waitForAdmissionRetry();
          continue;
        }
      }
      if (isTerminalStatus(admission.status)) {
        try {
          const snapshot = await getRunStatus(admission.run_id);
          if (!attemptIsCurrent(attempt)) return;
          countRef.current = snapshot.event_count;
          setCount(snapshot.event_count);
          setTotal(snapshot.total);
          if (snapshot.manifest) { setManifest(snapshot.manifest); setManifestOwnerId(snapshot.run_id); }
          if (!isTerminalStatus(snapshot.status)) {
            settleAdmissionWithOwner(
              {
                admission_id: snapshot.admission_id ?? admission.admission_id,
                run_id: snapshot.run_id,
                technique_id: admission.technique_id,
                vendor: snapshot.vendor,
                status: snapshot.status,
                event_count: snapshot.event_count,
                total: snapshot.total,
              },
              `The start response was unavailable, but ${admission.technique_id} was recovered from its run status.`,
            );
            return;
          }
        } catch (statusError) {
          if (!attemptIsCurrent(attempt)) return;
          if (statusError instanceof ApiError && statusError.status === 404) {
            await reconcileCurrentOwnerAfterAdmission(
              attempt,
              admission.status === "done"
                ? `${admission.technique_id} completed before the live stream could attach.`
                : `start failed: ${failureMessage}`,
            );
            return;
          }
          if (
            statusError instanceof ApiError
            && statusError.status >= 400
            && statusError.status < 500
          ) {
            settleAdmissionWithOwner(
              ownerFromAdmission(admission),
              `The terminal run is known, but its final evidence is unavailable because this browser session is no longer authorized. Reopen the URL printed by replicant web.`,
            );
            return;
          }
          await waitForAdmissionRetry();
          continue;
        }
        await reconcileCurrentOwnerAfterAdmission(
          attempt,
          admission.status === "done"
            ? `${admission.technique_id} completed before the live stream could attach.`
            : `start failed: ${failureMessage}`,
        );
        return;
      }
      await waitForAdmissionRetry();
    }
  }

  async function handleStart() {
    if (!technique || starting || startPendingRef.current) return;
    reset();
    setRunSending(sending);
    const body = buildBody();
    if (!body) return;
    setRunDraft({ body, name: technique.name });
    let admissionId: string;
    try {
      admissionId = createAdmissionId();
    } catch {
      setError("This browser cannot create a secure run admission identity.");
      return;
    }
    const attempt = ++startAttemptGenerationRef.current;
    startPendingRef.current = true;
    // The mount/selection probe describes the instant before admission began.
    // It must not be allowed to publish an owner while this POST is pending.
    activeProbeGenerationRef.current += 1;
    setStarting(true);
    onRunAdmissionChange?.({ technique_id: technique.id, vendor });
    let acceptedOwner: ActiveRun | null = null;
    let reservation: RunAdmissionState | null = null;
    try {
      reservation = await reserveAdmissionWithRetry(
        attempt,
        admissionId,
        technique.id,
        vendor,
      );
      if (!reservation || !attemptIsCurrent(attempt)) return;
      const { run_id, vendor: startedVendor, total: est, output_path: outputPath } = await startRun({
        ...body,
        admission_id: reservation.admission_id,
      });
      if (!mountedRef.current || attempt !== startAttemptGenerationRef.current) return;
      // A technique-change refresh may have started after admission began.
      // The POST response is newer and authoritative, so invalidate it again.
      activeProbeGenerationRef.current += 1;
      startPendingRef.current = false;
      runIdRef.current = run_id;
      runTechniqueRef.current = technique.id;
      runVendorRef.current = startedVendor;
      setRunDraft((current) => current ? { ...current, outputPath } : current);
      // The server accepted this run, so any external owner committed by a
      // pre-start /active response is stale. Clear it before setting `running`;
      // React batches these updates and the parent sees B directly, never A or
      // an unlocked gap.
      commitLockedBy(null);
      const localOwner: ActiveRun = {
        admission_id: reservation.admission_id,
        run_id,
        technique_id: technique.id,
        vendor: startedVendor,
        status: "running",
        event_count: 0,
        total: est,
      };
      acceptedOwner = localOwner;
      // Publish the real owner before ending admission. Both parent updates
      // happen in this continuation, so App cannot briefly unlock the vendor.
      onActiveRunChange?.(localOwner);
      onRunAdmissionChange?.(null);
      setLockProbeComplete(true);
      setTotal(est);
      setStarting(false);
      setRunning(true);
      const es = new EventSource(runEventsUrl(run_id));
      esRef.current = es;
      es.onmessage = (evt) => {
        if (!mountedRef.current || runIdRef.current !== run_id) return;
        const item = JSON.parse(evt.data);
        if (item.type === "line") {
          const arr = linesRef.current;
          arr.push(item.data);
          if (arr.length > MAX_VISIBLE) arr.splice(0, arr.length - MAX_VISIBLE);
          countRef.current = Math.max(countRef.current, arr.length);
          setCount((c) => Math.max(c, arr.length));
        } else if (item.type === "progress") {
          countRef.current = item.count;
          setCount(item.count);
        } else if (item.type === "done") {
          countRef.current = item.count;
          setCount(item.count);
          setManifest(item.manifest);
          setManifestOwnerId(run_id);
          holdLocalTerminalUntilOwnerConfirmed(
            run_id,
            item.status ?? "done",
            item.count,
            est,
          );
          es.close();
        } else if (item.type === "error") {
          countRef.current = Math.max(countRef.current, item.count ?? 0);
          setCount((current) => Math.max(current, item.count ?? 0));
          if (item.manifest) { setManifest(item.manifest); setManifestOwnerId(run_id); }
          setError(item.message);
          holdLocalTerminalUntilOwnerConfirmed(run_id, "error", countRef.current, est);
          es.close();
        }
      };
      es.onerror = () => {
        if (!mountedRef.current || runIdRef.current !== run_id) return;
        es.close();
        // A dropped SSE stream is not run completion: the backend worker may still
        // be emitting. Keep the run active (Stop stays available) and poll the
        // authoritative status until the backend itself reports terminal.
        setError("live stream interrupted; polling run status…");
        void pollRunUntilTerminal({
          getStatus: () => getRunStatus(run_id),
          onProgress: (c) => {
            if (!mountedRef.current || runIdRef.current !== run_id) return;
            countRef.current = Math.max(countRef.current, c);
            setCount((x) => Math.max(x, c));
          },
          onTerminal: (snap) => {
            if (!mountedRef.current || runIdRef.current !== run_id) return;
            countRef.current = Math.max(countRef.current, snap.event_count);
            setCount((x) => Math.max(x, snap.event_count));
            if (snap.manifest) { setManifest(snap.manifest as Manifest); setManifestOwnerId(run_id); }
            setError(snap.status === "error" ? "run failed" : null);
            holdLocalTerminalUntilOwnerConfirmed(
              run_id,
              snap.status,
              snap.event_count,
              est,
            );
          },
          onFetchError: (statusError) => {
            if (
              statusError instanceof ApiError
              && statusError.status === 404
              && mountedRef.current
              && runIdRef.current === run_id
            ) {
              // The bounded status history can lose this handle after terminal
              // completion while the SSE path is disconnected. Preserve A as a
              // reconciling owner, then let the restored-run watcher transfer
              // directly to the current active owner or release the lock.
              const knownOwner = lockedByRef.current;
              if (!knownOwner?.run_id || knownOwner.run_id === run_id) {
                commitLockedBy({
                  admission_id: reservation?.admission_id,
                  run_id,
                  technique_id: runTechniqueRef.current,
                  vendor: runVendorRef.current,
                  status: "reconciling",
                  event_count: countRef.current,
                  total: est,
                });
              }
              setRunning(false);
              return "stop";
            }
            return "retry";
          },
          sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
          // Stop polling if the view unmounts or a newer run supersedes this one.
          isCancelled: () => !mountedRef.current || runIdRef.current !== run_id,
        });
      };
    } catch (err) {
      if (!mountedRef.current || attempt !== startAttemptGenerationRef.current) return;
      // The run was accepted and published, but attaching its stream failed.
      // Fall back to the restored-run watcher so it remains visible/stoppable.
      if (acceptedOwner) {
        commitLockedBy(acceptedOwner);
        setError(`run accepted, but the live stream could not attach: ${(err as Error).message}`);
        setStarting(false);
        setRunning(false);
        return;
      }
      // A 409 is not a failure to report and forget: another run holds the lock,
      // and the operator needs to know which one and be able to end it. The
      // structured detail is what makes that possible.
      if (err instanceof ApiError && err.status === 409) {
        const detail = err.detail as {
          admission_id?: string;
          run_id?: string;
          technique_id?: string;
          vendor?: string;
          status?: string;
        } | null;
        if (detail?.run_id) {
          settleAdmissionWithOwner(
            {
              admission_id: detail.admission_id ?? null,
              run_id: detail.run_id,
              technique_id: detail.technique_id ?? null,
              vendor: detail.vendor ?? null,
              status: detail.status ?? "running",
            },
            err.message,
          );
        } else if (reservation) {
          setError(`start rejected: ${err.message}`);
          void reconcileUncertainStart(attempt, reservation, err.message);
        } else {
          settleAdmissionWithoutOwner(`start rejected: ${err.message}`);
        }
        return;
      }
      // A non-conflict 4xx response is a definitive rejection, not a reason to
      // wait for an unknown owner. If reservation already succeeded, resolve or
      // cancel that exact known identity before releasing its lock.
      if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
        const message = err.status === 401
          ? `start rejected: this browser session is no longer authorized. Reopen the URL printed by replicant web and try again. ${err.message}`
          : `start rejected: ${err.message}`;
        setError(message);
        if (reservation) {
          // A 422 can be produced before the start handler claims or releases
          // the known reservation. Resolve or cancel that exact server record.
          void reconcileUncertainStart(attempt, reservation, err.message);
        } else {
          settleAdmissionWithoutOwner(message);
        }
        return;
      }
      // The reservation was acknowledged before this request. Resolve that
      // exact identity instead of inferring acceptance from time or empty
      // active-owner snapshots.
      setError(`start response unavailable; checking its admission record: ${(err as Error).message}`);
      setRunning(false);
      if (reservation) {
        void reconcileUncertainStart(attempt, reservation, (err as Error).message);
      } else {
        settleAdmissionWithoutOwner(`start failed: ${(err as Error).message}`);
      }
    }
  }

  async function handleStop() {
    if (runIdRef.current) await stopRun(runIdRef.current).catch(() => undefined);
  }

  /** Request a stop, then hold the lock until the backend reports terminal. */
  async function handleStopLocked() {
    const runId = lockedBy?.run_id;
    if (!runId || stoppingLockedRunIdRef.current) return;

    stoppingLockedRunIdRef.current = runId;
    setStoppingLockedRunId(runId);
    setError(null);
    try {
      await stopRun(runId);
    } catch (err) {
      if (!mountedRef.current || stoppingLockedRunIdRef.current !== runId) return;
      stoppingLockedRunIdRef.current = null;
      setStoppingLockedRunId(null);
      setError(`could not request stop: ${(err as Error).message}`);
    }
  }

  if (!technique) {
    return (
      <div className="flex h-full min-h-[320px] items-center justify-center">
        <div className="max-w-xs text-center">
          <svg viewBox="0 0 200 22" preserveAspectRatio="none" className="mx-auto mb-4 h-5 w-40">
            <line x1="0" y1="17" x2="200" y2="17" stroke="hsl(var(--text-4))" strokeWidth="1.4" strokeDasharray="2 3" />
          </svg>
          <p className="text-sm text-muted-foreground">Select a technique to arm a run.</p>
        </div>
      </div>
    );
  }

  const canRun =
    technique.implemented
    && lockProbeComplete
    && !starting
    && !running
    && !lockedBy
    && !rateError;
  const lockedRunIsStopping =
    Boolean(lockedBy?.run_id) && stoppingLockedRunId === lockedBy?.run_id;
  const lockedRunIsTerminal = Boolean(
    lockedBy?.status && isTerminalStatus(lockedBy.status),
  );
  const lockedRunIsReserved = lockedBy?.status === "reserved";
  const lockedRunIsAdmitting = lockedBy?.status === "admitting";
  const lockedRunIsAdmission = lockedRunIsReserved || lockedRunIsAdmitting;
  const lockedRunIsReconciling = lockedBy?.status === "reconciling";
  const lockedRunControlDisabled =
    lockedRunIsStopping || lockedRunIsTerminal || lockedRunIsReconciling;
  const pct = total > 0 ? Math.min(100, Math.round((count / total) * 100)) : running ? 5 : 0;
  const manifestHeading =
    manifest?.status === "error"
      ? `Run failed · ${manifest.partial ? "partial manifest written" : "manifest written"}`
      : manifest?.status === "stopped"
        ? `Run stopped · ${manifest.partial ? "partial manifest written" : "manifest written"}`
        : manifest?.status === "running"
          ? "Run interrupted · last durable checkpoint"
          : "Run complete · manifest written";

  // The button says where the events go. Two switches above it decided that
  // silently before, and a run with both off renders everything and delivers
  // nothing while looking identical to a working run: same event stream, same
  // progress, same eps figure, because all three measure rendering. That cost a
  // live lab session, with tcpdump showing no packets and nothing explaining why.
  const destinationLabel = sending
    ? `Run and send to ${collector?.host}:${collector?.port}`
    : toFile
      ? "Run and write to file"
      : "Run without sending";

  const remoteManifest = manifestOwnerId !== null && manifestOwnerId !== runIdRef.current;
  const draftChanged = !remoteManifest && runDraft !== null && JSON.stringify(buildBody()) !== JSON.stringify(runDraft.body);
  const hasResult = runDraft !== null || running || manifest !== null || count > 0;
  const resultVendor = typeof manifest?.vendor === "string" && manifest.vendor
    ? manifest.vendor : runDraft?.body.vendor ?? lockedBy?.vendor ?? vendor;
  const manifestElapsed = manifest?.ended_at
    ? (Date.parse(manifest.ended_at) - Date.parse(manifest.started_at)) / 1000 : NaN;
  const resultTechnique = manifest?.technique_id ?? runDraft?.body.technique_id;
  const outputSummary = sending
    ? `${collector?.host}:${collector?.port} · ${collector?.transport.toUpperCase()}${toFile ? ` + ${filePath}` : ""}`
    : toFile ? filePath : "Browser events only · no send";

  const intensityChoices = ["low", "medium", "high"].filter((value) =>
    technique.intensities.length === 0 || technique.intensities.includes(value));

  return (
    <div className="mx-auto max-w-[1240px]">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-5">
        <div className="min-w-0">
          <h1 className="text-3xl font-medium tracking-tight">New detection test</h1>
          <p className="mt-2 text-body text-muted-foreground">Choose a technique, shape the signal, and inspect the result.</p>
        </div>
        <div className="min-w-0 max-w-full space-y-2">
          <div className="flex flex-wrap gap-2">
            <button onClick={handleStart} disabled={!canRun} className="action-button max-w-full">
              <Play aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />{destinationLabel}
            </button>
            <button onClick={handleStop} disabled={!running} className="quiet-button">
              <Square aria-hidden="true" className="h-3 w-3" />Stop run
            </button>
          </div>
          <p className="font-mono text-micro text-muted-foreground">{technique.id} · {vendorShortLabel(vendor)}</p>
        </div>
      </div>
      {/* Another run holds the single-run lock. Stated here, beside the button it
          disables, because the previous behaviour was a dead button and a 409
          quoting a hex id: the operator had no way to tell a busy server from a
          broken one, and reported it as "I press start and nothing happens". */}
      {lockedBy && (
        <div
          role="status"
          className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-btn border border-destructive/50 p-3 text-body leading-relaxed text-destructive"
        >
          <span>
            {lockedRunIsTerminal
              ? `${lockedBy.technique_id ?? "The active run"} reached ${lockedBy.status}. Confirming active run ownership with the backend.`
              : lockedRunIsStopping
              ? `Stop requested for ${lockedBy.technique_id ?? "the active run"}. Waiting for the backend to report a terminal state.`
              : lockedRunIsReconciling
              ? `${lockedBy.technique_id ?? "The previous run"} no longer has a status record. Confirming current run ownership with the backend.`
              : lockedRunIsReserved
              ? `${lockedBy.technique_id ?? "Another run"} holds an unclaimed run admission awaiting start. Cancel it if the request was abandoned.`
              : lockedRunIsAdmitting
              ? `${lockedBy.technique_id ?? "Another run"} holds run admission while the server prepares it.`
              : `${lockedBy.technique_id ?? "Another run"} is already running, and only one run may be active at a time so the events-per-second cap still means something.`}
            {typeof lockedBy.total === "number" && lockedBy.total > 0
              ? ` ${lockedBy.event_count ?? 0} of ${lockedBy.total} events so far.`
              : ""}
          </span>
          <button
            onClick={handleStopLocked}
            disabled={lockedRunControlDisabled}
            aria-busy={lockedRunControlDisabled || undefined}
            className="inline-flex items-center rounded-btn border border-destructive/50 px-2.5 py-1.5 font-mono text-label uppercase tracking-[-0.24px] transition-colors enabled:hover:border-destructive disabled:cursor-wait disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {lockedRunIsTerminal
              ? `Checking ${lockedBy.technique_id ?? "run"}…`
              : lockedRunIsStopping
              ? `Stopping ${lockedBy.technique_id ?? "run"}…`
              : lockedRunIsReconciling
              ? `Checking ${lockedBy.technique_id ?? "run"}…`
              : lockedRunIsAdmission
              ? `Cancel admission for ${lockedBy.technique_id ?? "run"}`
              : `Stop the running ${lockedBy.technique_id ?? "run"}`}
          </button>
        </div>
      )}

      {!lockProbeComplete && !lockedBy && (
        <p
          data-testid="active-owner-discovery"
          className="mt-4 text-body leading-relaxed text-text-3"
        >
          Confirming active run ownership with the backend. Run controls remain locked until
          the server responds.
        </p>
      )}


      {error && <div role="alert" className="mb-4 mt-4 rounded-btn border border-destructive/50 p-3 text-body text-destructive">{error}</div>}
      <div className="mt-4 grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <section className="panel">
            <div className="section-title"><span className="step-number">01</span><h2>Technique</h2>
              {onChooseTechnique && <button onClick={onChooseTechnique} disabled={starting} className="disabled:opacity-50 ml-auto flex items-center gap-1 text-label text-muted-foreground hover:text-foreground">Change <ChevronRight aria-hidden="true" className="h-3.5 w-3.5" /></button>}
            </div>
            <div className="rounded-btn border border-selection bg-selected p-4">
              <div className="flex items-center justify-between gap-2 font-mono text-micro text-muted-foreground">
                <span>{technique.id} · {technique.tactics.map((t) => t.replace(/^TA\d{4}\s+/, "")).join(", ")}</span>
                <Check aria-hidden="true" className="h-4 w-4 shrink-0 text-signal" />
              </div>
              <h3 className="mb-2 mt-2 text-lg font-medium leading-snug">{technique.name}</h3>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {[...technique.attack, ...technique.logical_families].map((tag) => <span key={tag} className="rounded border border-border bg-well px-2 py-0.5 font-mono text-micro">{tag}</span>)}
              </div>
            </div>
            {!technique.implemented && <p className="mt-3 text-body text-destructive">This catalog entry is not available to run yet.</p>}
          </section>
          <section className="panel">
            <div className="section-title"><span className="step-number">02</span><h2>Run settings</h2></div>
            {vendorControls}
            <div className="mt-4 grid grid-cols-1 items-end gap-3 min-[460px]:grid-cols-[minmax(0,1fr)_100px]">
              <div>
                <div className="u-label mb-2">Intensity</div>
                <div role="radiogroup" aria-label="Intensity" className="flex flex-wrap gap-1.5">
                  {intensityChoices.map((value) => <button key={value}
                    role="radio" aria-checked={intensity === value} onClick={() => setIntensity(value)} className="selection-button min-w-fit flex-auto whitespace-nowrap capitalize">
                    {intensity === value && <Check aria-hidden="true" className="h-3 w-3 shrink-0 text-signal" />}{value}
                  </button>)}
                </div>
              </div>
              <div><label className="u-label mb-2 block" htmlFor="duration">Duration</label>
                <Input id="duration" className="h-10 font-mono text-data" placeholder="preset" value={duration} onChange={(e) => setDuration(e.target.value)} />
              </div>
            </div>
            <p className="mt-2 text-label text-muted-foreground">Duration sets the event-time span. Pacing controls how long the run takes.</p>
            {technique.id === "REP-009" && (
              <div className="mt-3 max-w-xs">
                <label className="u-label mb-2 block">IPS signatures</label>
                <Select
                  value={signatureMode}
                  onValueChange={(value) => setSignatureMode(value as "mixed" | "single")}
                >
                  <SelectTrigger aria-label="IPS signature mode"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="mixed">Mixed signatures</SelectItem>
                    <SelectItem value="single">One repeated signature</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <details className="mt-3 rounded-btn border bg-well p-3">
              <summary className="text-label text-muted-foreground">{intensity.charAt(0).toUpperCase() + intensity.slice(1)} preset parameters</summary>
              <dl className="mt-3 grid grid-cols-2 gap-3 text-label">
                {Object.entries(technique.params[intensity] ?? {}).map(([key, value]) => <div key={key} className="min-w-0">
                  <dt className="text-muted-foreground">{key.replace(/_/g, " ")}</dt><dd className="break-words font-mono text-foreground">{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
                </div>)}
              </dl>
              <p className="mt-2 text-label text-muted-foreground">Catalog defaults. An entered duration overrides the preset span.</p>
            </details>
            <details className="mt-4 border-t pt-4">
              <summary className="text-sm font-medium">Advanced settings <span className="ml-1 text-label font-normal text-muted-foreground">Seed, rate, event time</span></summary>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div><label className="u-label mb-2 block" htmlFor="seed">Seed</label>
                  <Input id="seed" className="font-mono text-data" value={seed} onChange={(e) => setSeed(e.target.value)} /></div>
                <div><label className="u-label mb-2 block" htmlFor="rate">Rate</label>
                  <Input id="rate" type="number" min={1} max={epsCap} step={1} inputMode="numeric" className="font-mono text-data"
                    placeholder={`${epsCap}/s`} title="Events per second. Blank uses the configured cap. Lower it if your collector drops events."
                    aria-invalid={rateError ? true : undefined} aria-describedby={rateError ? "rate-error" : undefined} value={rate} onChange={(e) => setRate(e.target.value)} /></div>
                <div><label className="u-label mb-2 block">Anchor</label>
                  <Select value={anchor} onValueChange={(value) => setAnchor(value as AnchorChoice)}>
                    <SelectTrigger aria-label="Event time anchor"><SelectValue /></SelectTrigger>
                    <SelectContent><SelectItem value="now">now</SelectItem><SelectItem value="fixed">fixed</SelectItem></SelectContent>
                  </Select></div>
              </div>
              <p className="mt-2 text-label text-muted-foreground">The same seed and settings reproduce the same plan. The sending ceiling is {epsCap} events/s.</p>
            </details>
            {rateError && <p id="rate-error" role="alert" className="mt-3 text-body text-destructive">{rateError}</p>}
      <div className="mt-3 rounded-lg border p-3">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <span className="u-label">Pacing</span>
          <div role="radiogroup" aria-label="Pacing" className="flex flex-wrap gap-4">
            {(["plan", "burst"] as const).map((choice) => {
              const projected = projectedFor(choice, preview);
              return (
                <label
                  key={choice}
                  className="flex items-center gap-2 text-body text-muted-foreground"
                >
                  <input
                    type="radio"
                    name="pace"
                    className="h-3.5 w-3.5 accent-signal"
                    checked={pace === choice}
                    onChange={() => setPace(choice)}
                  />
                  <span>
                    {choice === "plan" ? "Plan time" : "Burst"}
                    {projected !== null && (
                      <b className="ml-1.5 font-mono text-micro font-normal text-foreground">
                        {fmtSpan(projected)}
                      </b>
                    )}
                  </span>
                </label>
              );
            })}
          </div>
          {pace === "plan" && (
            <div className="flex items-center gap-2">
              <label className="u-label" htmlFor="speed">
                Speed
              </label>
              <Input
                id="speed"
                className="h-8 w-16 font-mono text-data"
                inputMode="numeric"
                title="Compress the plan timeline. Event times compress with it."
                value={speed}
                onChange={(e) => setSpeed(e.target.value)}
              />
              <span className="text-body text-text-3">x</span>
            </div>
          )}
        </div>
        <p
          data-testid="pace-consequence"
          className="mt-2 text-body leading-relaxed text-muted-foreground"
        >
          {paceConsequence(pace, speedNum, preview)}
        </p>
      </div>


          </section>
          <section className="panel">
            <div className="section-title"><span className="step-number">03</span><h2>Output</h2></div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className={cn("flex items-center justify-between gap-3 rounded-btn border p-3 text-body", sending && "border-selection bg-selected")}>
                Collector<Switch checked={sendToCollector} onCheckedChange={setSendChoice} disabled={!collector} />
              </label>
              <label className={cn("flex items-center justify-between gap-3 rounded-btn border p-3 text-body", toFile && "border-selection bg-selected")}>
                File<Switch checked={toFile} onCheckedChange={setToFile} />
              </label>
            </div>
            <p className="mt-3 break-all font-mono text-data">{outputSummary}</p>
            <p className="mt-2 text-label text-muted-foreground">Every run records a manifest. Collector and file output can be enabled together.</p>
            {toFile && <div className="mt-3"><label htmlFor="file-path" className="u-label mb-2 block">Output file name</label>
              <Input id="file-path" className="font-mono text-data" value={filePath} onChange={(e) => setFilePath(e.target.value)} />
              <p className="mt-2 text-label text-muted-foreground">Files go in the server’s output directory. The resolved path appears with the run.</p></div>}
            {!collector && <p className="mt-3 text-label text-muted-foreground">No collector configured. Sends fail closed. Connect one, or write to file.</p>}
            {onConfigureCollector && <button onClick={onConfigureCollector} disabled={starting} className="quiet-button mt-3">{collector ? "Edit collector" : "Configure collector"}<ChevronRight aria-hidden="true" className="h-3.5 w-3.5" /></button>}
            {collector && !sending && !toFile && <div role="status" className="mt-3 rounded-btn border border-destructive/50 p-3 text-body text-destructive">
              No destination selected. This run will render events and neither send nor write
              them, and the readout will still show a rate, because it measures rendering. Turn
              on Collector to send to {collector.host}:{collector.port}.
            </div>}
            {anchorNotice(anchor, sending, anchorEpoch) && <div role="status" className="mt-3 rounded-btn border border-destructive/50 p-3 text-body text-destructive">{anchorNotice(anchor, sending, anchorEpoch)}</div>}
          </section>
        </div>
        <div className="min-w-0 space-y-4">
          {hasResult && <section aria-label="Run result" className="min-w-0">
            <div className="panel">
              <h2 className="text-sm font-medium">{running ? "Active run" : "Latest run evidence"}</h2>
              <p className="mt-2 break-words font-mono text-label">{resultTechnique} · {vendorShortLabel(resultVendor)}</p>
              {!remoteManifest && runDraft && <p data-testid="run-destination" className="mt-2 break-all text-label text-muted-foreground">
                {runDraft.body.no_send ? "No send" : `${runDraft.body.collector?.host}:${runDraft.body.collector?.port} · ${runDraft.body.collector?.transport.toUpperCase()}`}
                {runDraft.body.to_file ? ` · File: ${runDraft.outputPath ?? (manifest?.transport === "file" ? manifest.target : "awaiting resolved path")}` : ""}
              </p>}
              {draftChanged && <p role="status" className="mt-3 border-t pt-3 text-label text-muted-foreground">The draft has changed. Run evidence retains its original technique, profile, and destination.</p>}
            </div>
            <SignalReadout eps={remoteManifest ? 0 : eps} cap={typeof manifest?.rate === "number" ? manifest.rate : runDraft?.body.rate ?? epsCap}
              capApplies={manifest ? ["udp", "tcp", "tls"].includes(manifest.transport) : runDraft ? !runDraft.body.no_send : runSending}
              samples={remoteManifest ? [] : samples} windowSeconds={Math.round((SAMPLE_WINDOW * SAMPLE_MS) / 1000)} pct={manifest?.planned_event_count ? Math.min(100, Math.round(manifest.event_count / manifest.planned_event_count * 100)) : pct}
              running={running} count={manifest?.event_count ?? count} total={manifest?.planned_event_count ?? total}
              elapsedLabel={remoteManifest ? (Number.isFinite(manifestElapsed) ? fmtDur(manifestElapsed) : "Unknown") : elapsed}
              rateAvailable={!remoteManifest} />
            {!remoteManifest && <div className="rounded-lg border bg-well p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <span className="u-label">Event stream · {runDraft?.body.vendor ?? resultVendor}</span>
                <span className="font-mono text-micro text-muted-foreground">last {MAX_VISIBLE}</span>
              </div>
              <div ref={logRef} tabIndex={0} aria-label="Event stream" className="scroll-thin h-40 overflow-auto font-mono text-data leading-[1.7] text-text-3">
                {linesRef.current.length === 0 ? <div className="text-label text-muted-foreground">{running ? "Waiting for events…" : "No streamed events captured in this browser."}</div>
                  : linesRef.current.map((line, i) => <CefLine key={i} line={line} className="whitespace-pre" />)}
              </div>
            </div>}
      {/* manifest */}
      {manifest && (
        <div className="mt-4 rounded-lg border bg-card p-4">
          <div className="mb-4 flex items-center gap-2 text-body">
            {manifest.status === undefined || manifest.status === "done" ? (
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-muted-foreground">
                <path d="M2.5 7.5 L5.5 10.5 L11.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            ) : (
              <span aria-hidden="true" className="font-mono text-signal">!</span>
            )}
            {manifestHeading}
          </div>
          {/* Audit fields. Two columns is the floor: these are short mono values
              and one column per row would make a seven-field manifest a scroll. */}
          <div className="grid grid-cols-2 gap-x-5 gap-y-3 sm:grid-cols-3 xl:grid-cols-2">
            {[
              [
                "events",
                typeof manifest.planned_event_count === "number"
                  ? `${manifest.event_count} / ${manifest.planned_event_count}`
                  : manifest.event_count,
              ],
              ["status", manifest.status ?? "done"],
              ["technique", manifest.technique_id],
              ["profile", typeof manifest.vendor === "string" ? vendorShortLabel(manifest.vendor) : resultVendor],
              ["seed", manifest.seed],
              ["intensity", manifest.intensity],
              ["use case", manifest.ndr_uc],
              ["target", manifest.target],
              ["transport", manifest.transport],
              ["anchor", manifest.anchor_epoch],
            ].map(([k, v]) => (
              <div
                key={k}
                className="u-label"
                data-testid={k === "events" ? "manifest-events" : undefined}
              >
                {k}
                <b className="mt-0.5 block break-all font-mono text-data font-normal normal-case tracking-normal text-foreground">
                  {String(v)}
                </b>
              </div>
            ))}
          </div>
          {manifest.warmup_note && (
            <div className="mt-3 font-mono text-micro text-text-3">note: {manifest.warmup_note}</div>
          )}
        </div>
      )}

          </section>}
          <TechniquePreview technique={technique} vendor={vendor} preview={preview} pending={previewPending} />
        </div>
      </div>
    </div>
  );
}
