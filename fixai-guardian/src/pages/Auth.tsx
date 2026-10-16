import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";

import { useAuth } from "@/hooks/use-auth";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Clock,
  HeartPulse,
  Laptop,
  Loader2,
  LogOut,
  Mail,
  RadioTower,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  UserCheck,
  UserX,
} from "lucide-react";
import { Suspense, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";

interface AuthProps {
  redirectAfterAuth?: string;
}

function resolveRedirectAfterAuth(
  returnTo: string | null,
  fallback = "/dashboard",
) {
  if (returnTo?.startsWith("/") && !returnTo.startsWith("//")) {
    return returnTo;
  }
  return fallback;
}

const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;

function Auth({ redirectAfterAuth }: AuthProps = {}) {
  const {
    isLoading: authLoading,
    isAuthenticated,
    user,
    activeOtp,
    sendOtp,
    resendOtp,
    verifyOtp,
    signIn,
    signOut,
  } = useAuth();

  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get("returnTo");
  const redirect = resolveRedirectAfterAuth(returnTo, redirectAfterAuth);

  const [step, setStep] = useState<"enterEmail" | { email: string }>("enterEmail");
  const [emailInput, setEmailInput] = useState("");
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);

  // Timers for Expiration (5 min = 300s) and Resend Cooldown (45s)
  const [expirySeconds, setExpirySeconds] = useState(300);
  const [cooldownSeconds, setCooldownSeconds] = useState(45);

  // Expiration countdown ticker
  useEffect(() => {
    if (typeof step === "object" && expirySeconds > 0) {
      const timer = setInterval(() => {
        setExpirySeconds((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [step, expirySeconds]);

  // Resend cooldown ticker
  useEffect(() => {
    if (typeof step === "object" && cooldownSeconds > 0) {
      const timer = setInterval(() => {
        setCooldownSeconds((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [step, cooldownSeconds]);

  // If user is already authenticated and came via an intercepted redirect from a protected page, navigate to destination
  if (!authLoading && isAuthenticated && returnTo) {
    navigate(redirect);
    return null;
  }

  // Format seconds to mm:ss
  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const s = secs % 60;
    return `${mins}:${s < 10 ? "0" : ""}${s}`;
  };

  // ── Step 1: Send OTP ──────────────────────────────────────────────────
  const handleSendOtp = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanEmail = emailInput.trim();

    if (!cleanEmail || !EMAIL_REGEX.test(cleanEmail)) {
      setError("Please enter a valid email address.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setSuccessBanner(null);

    try {
      const result = await sendOtp(cleanEmail);
      setSuccessBanner(result.message || "OTP sent successfully to your email.");
      toast.success("OTP sent successfully to your email.");
      setCooldownSeconds(result.cooldownSeconds || 45);
      setExpirySeconds(result.expiresInSeconds || 300);
      setStep({ email: cleanEmail });
      setOtp("");
    } catch (err: any) {
      console.error("Send OTP error:", err);
      const msg = err.message || "Unable to send OTP. Please try again.";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // ── Step 2: Resend OTP ────────────────────────────────────────────────
  const handleResendOtp = async () => {
    if (cooldownSeconds > 0 || typeof step !== "object") return;
    setIsLoading(true);
    setError(null);

    try {
      const result = await resendOtp(step.email);
      setSuccessBanner("OTP sent successfully to your email.");
      toast.success("OTP sent successfully to your email.");
      setCooldownSeconds(result.cooldownSeconds || 45);
      setExpirySeconds(result.expiresInSeconds || 300);
      setOtp("");
    } catch (err: any) {
      console.error("Resend OTP error:", err);
      const msg = err.message || "Unable to send OTP. Please try again.";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // ── Step 3: Verify OTP ────────────────────────────────────────────────
  const handleVerifyOtp = async (e?: React.FormEvent, codeToSubmit?: string) => {
    if (e) e.preventDefault();
    if (typeof step !== "object") return;

    const submittedCode = (codeToSubmit || otp).trim();

    if (!submittedCode || submittedCode.length !== 6) {
      setError("Please enter a complete 6-digit OTP.");
      return;
    }

    if (expirySeconds <= 0) {
      setError("OTP expired");
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const result = await verifyOtp(step.email, submittedCode);
      toast.success("Authentication successful! Welcome to FixAI.");
      navigate(redirect);
    } catch (err: any) {
      console.error("Verify OTP error:", err);
      const msg = err.message || "Invalid OTP";
      setError(msg);
      toast.error(msg);
      if (msg === "Invalid OTP" || msg === "OTP expired") {
        setOtp("");
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Quick 1-Click Host Operator Access
  const handleHostOperatorLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("host-operator");
      toast.success("Signed in as Host System Operator");
      navigate(redirect);
    } catch (err: any) {
      setError("Failed to sign in as Host Operator.");
    } finally {
      setIsLoading(false);
    }
  };

  // Quick 1-Click Guest Access
  const handleGuestLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("anonymous");
      toast.success("Signed in as Guest Security Analyst");
      navigate(redirect);
    } catch (err: any) {
      setError("Failed to sign in as guest.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="flex items-center justify-center h-full flex-col w-full max-w-md">

          {/* If already signed in and visiting /auth directly, show active session card */}
          {isAuthenticated ? (
            <Card className="w-full border border-border/80 shadow-2xl bg-card">
              <CardHeader className="text-center pb-2">
                <div className="flex justify-center mb-2">
                  <div className="size-14 rounded-2xl bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 flex items-center justify-center shadow-sm">
                    <ShieldCheck className="size-8 animate-pulse" />
                  </div>
                </div>
                <CardTitle className="text-xl font-bold">
                  Active Session Authenticated
                </CardTitle>
                <CardDescription className="text-xs">
                  Connected to local endpoint system · Hardware EDR active
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 pt-2">
                <div className="rounded-xl border border-border/70 bg-muted/40 p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <UserCheck className="size-3.5 text-primary" /> Operator
                    </span>
                    <strong className="font-semibold text-foreground">
                      {user?.name || "Host Operator"}
                    </strong>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <Mail className="size-3.5 text-primary" /> Identity
                    </span>
                    <span className="font-mono text-muted-foreground text-[11px]">
                      {user?.email || "operator@fixai.local"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <Laptop className="size-3.5 text-emerald-500" /> Monitored Host
                    </span>
                    <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                      Local Machine (psutil)
                    </span>
                  </div>
                </div>

                <div className="flex flex-col gap-2 pt-1">
                  <Button
                    onClick={() => navigate(redirect)}
                    className="w-full gap-2 font-bold shadow-sm"
                  >
                    Open Dashboard
                    <ArrowRight className="size-4" />
                  </Button>
                  <Button
                    variant="outline"
                    onClick={async () => {
                      await signOut();
                    }}
                    className="w-full gap-2 text-xs text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                  >
                    <LogOut className="size-3.5" />
                    Sign out / Switch user
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card className="w-full border border-border/80 shadow-2xl bg-card overflow-hidden">
              {step === "enterEmail" ? (
                <>
                  <CardHeader className="text-center pb-3">
                    <div className="flex justify-center">
                      <button
                        type="button"
                        aria-label="FixAI home"
                        onClick={() => navigate("/")}
                        className="mb-3 mt-1 flex size-14 cursor-pointer items-center justify-center rounded-2xl bg-gradient-to-br from-primary via-emerald-500 to-cyan-500 text-primary-foreground shadow-md transition-transform hover:scale-105"
                      >
                        <HeartPulse className="size-7 animate-pulse" />
                      </button>
                    </div>
                    <CardTitle className="text-2xl font-bold tracking-tight">
                      Sign in to Fix<span className="text-primary">AI</span>
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Enter your email to receive a secure 6-digit verification OTP
                    </CardDescription>

                    {/* Local Machine Status Badge */}
                    <div className="mt-2.5 inline-flex items-center justify-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 mx-auto">
                      <RadioTower className="size-3 animate-pulse text-emerald-500" />
                      <span>Local Endpoint Ready (127.0.0.1:8000)</span>
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-4">
                    {/* Email Form */}
                    <form onSubmit={handleSendOtp} className="space-y-3">
                      <div>
                        <label className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block mb-1.5">
                          Email Address
                        </label>
                        <div className="relative">
                          <Mail className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
                          <Input
                            name="email"
                            placeholder="name@company.com"
                            type="email"
                            value={emailInput}
                            onChange={(e) => setEmailInput(e.target.value)}
                            className="pl-9 h-10 text-xs"
                            disabled={isLoading}
                            required
                            autoFocus
                          />
                        </div>
                      </div>

                      {error && (
                        <div className="flex items-center gap-2 p-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs font-medium">
                          <AlertCircle className="size-4 shrink-0" />
                          <span>{error}</span>
                        </div>
                      )}

                      <Button
                        type="submit"
                        className="w-full gap-2 h-10 font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
                        disabled={isLoading || !emailInput.trim()}
                      >
                        {isLoading ? (
                          <>
                            <Loader2 className="size-4 animate-spin" />
                            Sending OTP to Email...
                          </>
                        ) : (
                          <>
                            Send OTP
                            <ArrowRight className="size-4" />
                          </>
                        )}
                      </Button>
                    </form>

                    <div className="relative my-2">
                      <div className="absolute inset-0 flex items-center">
                        <span className="w-full border-t border-border/60" />
                      </div>
                      <div className="relative flex justify-center text-[10px] uppercase font-semibold">
                        <span className="bg-card px-2 text-muted-foreground">
                          Or quick access
                        </span>
                      </div>
                    </div>

                    {/* Quick Access Options */}
                    <div className="space-y-2">
                      <Button
                        type="button"
                        variant="secondary"
                        className="w-full gap-2 h-9 text-xs font-semibold"
                        onClick={handleHostOperatorLogin}
                        disabled={isLoading}
                      >
                        <ShieldCheck className="size-3.5 text-primary" />
                        Sign In as Host System Operator
                      </Button>

                      <Button
                        type="button"
                        variant="outline"
                        className="w-full text-xs text-muted-foreground hover:text-foreground h-9"
                        onClick={handleGuestLogin}
                        disabled={isLoading}
                      >
                        <UserX className="mr-2 size-3.5" />
                        Continue as Guest Security Analyst
                      </Button>
                    </div>
                  </CardContent>
                </>
              ) : (
                /* ── Step 2: OTP Verification Screen ───────────────────────── */
                <>
                  <CardHeader className="text-center pb-2">
                    <div className="flex justify-center mb-2">
                      <div className="size-12 rounded-xl bg-primary/10 text-primary flex items-center justify-center border border-primary/20 shadow-xs">
                        <Mail className="size-6 animate-pulse" />
                      </div>
                    </div>
                    <CardTitle className="text-xl font-bold">Verify Your Email</CardTitle>
                    <CardDescription className="text-xs">
                      Enter the 6-digit code sent to <strong className="text-foreground">{step.email}</strong>
                    </CardDescription>
                  </CardHeader>

                  <form onSubmit={handleVerifyOtp}>
                    <CardContent className="space-y-4 pb-2">
                      {/* Success Banner */}
                      {successBanner && (
                        <div className="flex items-center gap-2 p-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-xs font-medium">
                          <CheckCircle2 className="size-4 shrink-0" />
                          <span>{successBanner}</span>
                        </div>
                      )}

                      {/* Error Banner */}
                      {error && (
                        <div className="flex items-center gap-2 p-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs font-medium">
                          <AlertCircle className="size-4 shrink-0" />
                          <span>{error}</span>
                        </div>
                      )}

                      {/* Dev / Relay OTP Banner (streamlines local development and testing) */}
                      {activeOtp && (
                        <div className="flex items-center justify-between rounded-xl border border-primary/30 bg-primary/5 px-3 py-2 text-xs">
                          <span className="text-muted-foreground text-[11px]">
                            Dispatched Code: <strong className="font-mono text-primary text-sm font-bold tracking-wider">{activeOtp}</strong>
                          </span>
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            className="h-6 px-2 text-[10px] font-bold"
                            onClick={() => {
                              setOtp(activeOtp);
                              handleVerifyOtp(undefined, activeOtp);
                            }}
                          >
                            Auto-fill & Verify
                          </Button>
                        </div>
                      )}

                      {/* 6-Digit OTP Input Box */}
                      <div className="flex justify-center py-2">
                        <InputOTP
                          value={otp}
                          onChange={(val) => {
                            setOtp(val);
                            if (val.length === 6 && !isLoading) {
                              handleVerifyOtp(undefined, val);
                            }
                          }}
                          maxLength={6}
                          disabled={isLoading}
                          autoFocus
                        >
                          <InputOTPGroup>
                            {Array.from({ length: 6 }).map((_, index) => (
                              <InputOTPSlot key={index} index={index} className="size-11 text-base font-bold font-mono" />
                            ))}
                          </InputOTPGroup>
                        </InputOTP>
                      </div>

                      {/* Timers row: Expiration & Resend Cooldown */}
                      <div className="flex items-center justify-between text-xs px-1 pt-1">
                        {/* Expiration Timer */}
                        <div className="flex items-center gap-1.5 text-muted-foreground text-[11px]">
                          <Clock className="size-3.5 text-amber-500" />
                          <span>
                            {expirySeconds > 0 ? (
                              <>Expires in: <strong className="font-mono font-semibold text-foreground">{formatTime(expirySeconds)}</strong></>
                            ) : (
                              <span className="text-rose-500 font-bold">OTP expired</span>
                            )}
                          </span>
                        </div>

                        {/* Resend OTP Button with Live Cooldown */}
                        <div>
                          {cooldownSeconds > 0 ? (
                            <span className="text-[11px] text-muted-foreground font-mono">
                              Resend in {cooldownSeconds}s
                            </span>
                          ) : (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-7 px-2 text-[11px] font-semibold text-primary hover:text-primary hover:bg-primary/10 gap-1"
                              onClick={handleResendOtp}
                              disabled={isLoading}
                            >
                              <RotateCcw className="size-3" />
                              Resend OTP
                            </Button>
                          )}
                        </div>
                      </div>
                    </CardContent>

                    <CardFooter className="flex-col gap-2 pt-2">
                      <Button
                        type="submit"
                        className="w-full font-bold h-10 gap-2"
                        disabled={isLoading || otp.length !== 6 || expirySeconds <= 0}
                      >
                        {isLoading ? (
                          <>
                            <Loader2 className="size-4 animate-spin" />
                            Verifying OTP...
                          </>
                        ) : (
                          <>
                            Verify & Enter Dashboard
                            <ArrowRight className="size-4" />
                          </>
                        )}
                      </Button>

                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() => {
                          setStep("enterEmail");
                          setError(null);
                          setSuccessBanner(null);
                        }}
                        disabled={isLoading}
                        className="w-full text-xs text-muted-foreground hover:text-foreground"
                      >
                        Use a different email
                      </Button>
                    </CardFooter>
                  </form>
                </>
              )}

              <div className="py-3 px-6 text-[11px] text-center text-muted-foreground bg-muted/50 border-t border-border/60">
                FixAI Autonomous Guardian · Zero-Trust Endpoint Protection
              </div>
            </Card>
          )}

        </div>
      </div>
    </div>
  );
}

export default function AuthPage(props: AuthProps) {
  return (
    <Suspense>
      <Auth {...props} />
    </Suspense>
  );
}
