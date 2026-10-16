/**
 * Safe Convex hook wrappers for offline / local-only mode.
 *
 * When the app runs without a real Convex deployment (VITE_CONVEX_URL is unset
 * or points to "mock.convex.cloud"), no <ConvexProvider> is in the React tree.
 * Raw hooks like `useConvexAuth()`, `useQuery()`, and `useMutation()` would
 * throw because they cannot find Convex provider context.
 *
 * These wrappers detect that condition at module-load time and export either
 * the real hook or a safe no-op replacement — obeying React's Rules of Hooks.
 */
import { useConvexAuth, useMutation, useQuery } from "convex/react";
import { useAuthActions } from "@convex-dev/auth/react";

// ── Detect Convex availability at module init (runs once) ────────────────
const rawConvexUrl = (import.meta as any).env?.VITE_CONVEX_URL || "";
export const isConvexAvailable: boolean =
  !!rawConvexUrl &&
  !rawConvexUrl.includes("mock.convex.cloud") &&
  rawConvexUrl.startsWith("https://");

// ── No-op hook replacements ─────────────────────────────────────────────
const NOOP_AUTH = { isLoading: false, isAuthenticated: false };

function useNoopConvexAuth() {
  return NOOP_AUTH;
}

function useNoopQuery<T = any>(_queryRef: any, _args?: any): T | undefined {
  return undefined;
}

const noopMutation = async (..._args: any[]): Promise<any> => undefined;

function useNoopMutation<T = any>(_mutationRef: any): (...args: any[]) => Promise<any> {
  return noopMutation;
}

function useNoopAuthActions() {
  return {
    signIn: async (..._args: any[]): Promise<any> => {},
    signOut: async (..._args: any[]): Promise<any> => {},
  };
}

// ── Export safe hooks ────────────────────────────────────────────────────
export const useSafeConvexAuth: typeof useConvexAuth = isConvexAvailable
  ? useConvexAuth
  : (useNoopConvexAuth as any);

export const useSafeQuery: typeof useQuery = isConvexAvailable
  ? useQuery
  : (useNoopQuery as any);

export const useSafeMutation: typeof useMutation = isConvexAvailable
  ? useMutation
  : (useNoopMutation as any);

export const useSafeAuthActions: typeof useAuthActions = isConvexAvailable
  ? useAuthActions
  : (useNoopAuthActions as any);
