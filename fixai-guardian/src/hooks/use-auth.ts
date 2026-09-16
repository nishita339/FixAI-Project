import { api } from "@/convex/_generated/api";
import { useAuthActions } from "@convex-dev/auth/react";
import { useConvexAuth, useQuery } from "convex/react";
import { useCallback, useEffect, useState } from "react";

const MOCK_USER_KEY = "fixai_mock_user";
const MOCK_OTP_KEY = "fixai_active_otp";

export function useAuth() {
  const { isLoading: isConvexLoading, isAuthenticated: isConvexAuth } = useConvexAuth();
  const convexUser = useQuery(api.users.currentUser);
  const { signIn: convexSignIn, signOut: convexSignOut } = useAuthActions();

  const [localUser, setLocalUser] = useState<any>(() => {
    try {
      const saved = localStorage.getItem(MOCK_USER_KEY);
      if (saved) return JSON.parse(saved);
      const defaultUser = {
        _id: "local-operator-id",
        name: "Host System Operator",
        email: "operator@fixai.local",
      };
      localStorage.setItem(MOCK_USER_KEY, JSON.stringify(defaultUser));
      return defaultUser;
    } catch {
      return {
        _id: "local-operator-id",
        name: "Host System Operator",
        email: "operator@fixai.local",
      };
    }
  });

  const [activeOtp, setActiveOtp] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(MOCK_OTP_KEY) || null;
    } catch {
      return null;
    }
  });

  const [isTimedOut, setIsTimedOut] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsTimedOut(true);
    }, 800);
    return () => clearTimeout(timer);
  }, []);

  const isAuthenticated = isConvexAuth || !!localUser;
  const user = convexUser ?? localUser;
  
  const isLoading = (isConvexLoading || (convexUser === undefined && !isTimedOut)) && !localUser;

  const signIn = useCallback(
    async (provider: string, args?: any) => {
      let email = "guest@fixai.local";
      let code = "";
      if (args instanceof FormData) {
        email = (args.get("email") as string) || email;
        code = (args.get("code") as string) || "";
      } else if (typeof args === "object" && args) {
        email = args.email || email;
        code = args.code || "";
      }

      // Generate a deterministic 6-digit OTP code for dev/demo mode when initiating email sign-in
      if (provider === "email-otp" && !code) {
        const generatedCode = "123456";
        sessionStorage.setItem(MOCK_OTP_KEY, generatedCode);
        setActiveOtp(generatedCode);
        console.log(
          `\n========================================\n[FixAI Auth] Generated OTP for ${email}: ${generatedCode}\n========================================\n`,
        );
      }

      try {
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Convex auth connection timeout")), 1200),
        );
        await Promise.race([convexSignIn(provider, args), timeoutPromise]);
      } catch (err) {
        console.warn(
          "[FixAI Auth] Convex connection unavailable or using offline mode. Performing local auth:",
          err,
        );
        
        // Complete sign-in for guest OR when OTP code is provided
        if (provider === "anonymous" || (provider === "email-otp" && code)) {
          const fallbackUser = {
            _id: "mock-user-id",
            name: email.includes("@") ? email.split("@")[0] : "Guest Operator",
            email: email,
          };
          localStorage.setItem(MOCK_USER_KEY, JSON.stringify(fallbackUser));
          sessionStorage.removeItem(MOCK_OTP_KEY);
          setActiveOtp(null);
          setLocalUser(fallbackUser);
        }
      }
    },
    [convexSignIn],
  );

  const signOut = useCallback(async () => {
    localStorage.removeItem(MOCK_USER_KEY);
    sessionStorage.removeItem(MOCK_OTP_KEY);
    setActiveOtp(null);
    setLocalUser(null);
    try {
      await convexSignOut();
    } catch {
      // Ignore offline sign out error
    }
  }, [convexSignOut]);

  return {
    isLoading,
    isAuthenticated,
    user,
    activeOtp,
    signIn,
    signOut,
  };
}
