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
  ArrowRight,
  CheckCircle2,
  HeartPulse,
  Laptop,
  Loader2,
  LogOut,
  Mail,
  RadioTower,
  ShieldCheck,
  UserCheck,
  UserX,
} from "lucide-react";
import { Suspense, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

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

function Auth({ redirectAfterAuth }: AuthProps = {}) {
  const { isLoading: authLoading, isAuthenticated, user, activeOtp, signIn, signOut } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get("returnTo");
  const redirect = resolveRedirectAfterAuth(returnTo, redirectAfterAuth);

  const [step, setStep] = useState<"signIn" | { email: string }>("signIn");
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // If user is already authenticated and came via a direct redirect from a protected page, proceed
  // Otherwise, if they visited /auth directly, display their active session with switch/logout controls
  if (!authLoading && isAuthenticated && returnTo) {
    navigate(redirect);
    return null;
  }

  const handleEmailSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const formData = new FormData(event.currentTarget);
      const emailStr = (formData.get("email") as string) || "";
      await signIn("email-otp", formData);
      setStep({ email: emailStr });
    } catch (error) {
      console.error("Email sign-in error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Failed to send verification code. Please try again.",
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const formData = new FormData(event.currentTarget);
      await signIn("email-otp", formData);
      navigate(redirect);
    } catch (error) {
      console.error("OTP verification error:", error);
      setError("The verification code you entered is incorrect.");
      setOtp("");
    } finally {
      setIsLoading(false);
    }
  };

  const handleHostOperatorLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("host-operator");
      navigate(redirect);
    } catch (error) {
      console.error("Host Operator login error:", error);
      setError("Failed to sign in as Host Operator.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("anonymous");
      navigate(redirect);
    } catch (error) {
      console.error("Guest login error:", error);
      setError("Failed to sign in as guest.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Auth Content */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="flex items-center justify-center h-full flex-col w-full max-w-md">

          {/* If already signed in, show session state & switch account option */}
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
              {step === "signIn" ? (
                <>
                  <CardHeader className="text-center pb-4">
                    <div className="flex justify-center">
                      <button
                        type="button"
                        aria-label="FixAI home"
                        onClick={() => navigate("/")}
                        className="mb-3 mt-2 flex size-14 cursor-pointer items-center justify-center rounded-2xl bg-gradient-to-br from-primary via-emerald-500 to-cyan-500 text-primary-foreground shadow-md transition-transform hover:scale-105"
                      >
                        <HeartPulse className="size-7 animate-pulse" />
                      </button>
                    </div>
                    <CardTitle className="text-2xl font-bold tracking-tight">
                      Sign in to Fix<span className="text-primary">AI</span>
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Authenticate to access live telemetry and autonomous healing on this system
                    </CardDescription>

                    {/* Local Machine Status Badge */}
                    <div className="mt-3 inline-flex items-center justify-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 mx-auto">
                      <RadioTower className="size-3 animate-pulse text-emerald-500" />
                      <span>Local Endpoint Ready (127.0.0.1:8000)</span>
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-4">
                    {/* Primary Option 1: Quick 1-Click Host Operator Access */}
                    <Button
                      type="button"
                      className="w-full gap-2 h-10 font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
                      onClick={handleHostOperatorLogin}
                      disabled={isLoading}
                    >
                      {isLoading ? (
                        <Loader2 className="size-4 animate-spin" />
                      ) : (
                        <ShieldCheck className="size-4" />
                      )}
                      Sign In as Host System Operator
                    </Button>

                    <div className="relative">
                      <div className="absolute inset-0 flex items-center">
                        <span className="w-full border-t border-border/60" />
                      </div>
                      <div className="relative flex justify-center text-[10px] uppercase font-semibold">
                        <span className="bg-card px-2 text-muted-foreground">
                          Or sign in with email OTP
                        </span>
                      </div>
                    </div>

                    {/* Primary Option 2: Email OTP Sign In */}
                    <form onSubmit={handleEmailSubmit}>
                      <div className="space-y-3">
                        <div className="relative flex items-center gap-2">
                          <div className="relative flex-1">
                            <Mail className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
                            <Input
                              name="email"
                              placeholder="operator@company.com"
                              type="email"
                              className="pl-9 h-10 text-xs"
                              disabled={isLoading}
                              required
                            />
                          </div>
                          <Button
                            type="submit"
                            variant="secondary"
                            className="h-10 px-3 shrink-0"
                            disabled={isLoading}
                          >
                            {isLoading ? (
                              <Loader2 className="size-4 animate-spin" />
                            ) : (
                              <span className="text-xs font-semibold flex items-center gap-1">
                                Send Code <ArrowRight className="size-3.5" />
                              </span>
                            )}
                          </Button>
                        </div>
                      </div>
                    </form>

                    {error && (
                      <p className="text-xs text-rose-500 text-center font-medium">{error}</p>
                    )}

                    {/* Option 3: Guest / Analyst Login */}
                    <div className="pt-1">
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
                <>
                  <CardHeader className="text-center pb-2">
                    <div className="flex justify-center mb-2">
                      <div className="size-12 rounded-xl bg-primary/10 text-primary flex items-center justify-center">
                        <Mail className="size-6" />
                      </div>
                    </div>
                    <CardTitle className="text-xl font-bold">Check your email</CardTitle>
                    <CardDescription className="text-xs">
                      Enter the 6-digit verification code sent to <strong className="text-foreground">{step.email}</strong>
                    </CardDescription>
                  </CardHeader>
                  <form onSubmit={handleOtpSubmit}>
                    <CardContent className="space-y-4 pb-4">
                      <input type="hidden" name="email" value={step.email} />
                      <input type="hidden" name="code" value={otp} />

                      {/* Instant Dev/Demo OTP Code Display with 1-click Auto-Fill */}
                      <div className="flex items-center justify-between rounded-xl border border-primary/30 bg-primary/5 px-3 py-2 text-xs">
                        <span className="text-muted-foreground text-[11px]">
                          Verification OTP: <strong className="font-mono text-primary text-sm font-bold tracking-wider">{activeOtp || "123456"}</strong>
                        </span>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          className="h-6 px-2 text-[10px] font-bold"
                          onClick={() => setOtp(activeOtp || "123456")}
                        >
                          Auto-fill
                        </Button>
                      </div>

                      <div className="flex justify-center py-2">
                        <InputOTP
                          value={otp}
                          onChange={setOtp}
                          maxLength={6}
                          disabled={isLoading}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && otp.length === 6 && !isLoading) {
                              const form = (e.target as HTMLElement).closest("form");
                              if (form) form.requestSubmit();
                            }
                          }}
                        >
                          <InputOTPGroup>
                            {Array.from({ length: 6 }).map((_, index) => (
                              <InputOTPSlot key={index} index={index} />
                            ))}
                          </InputOTPGroup>
                        </InputOTP>
                      </div>

                      {error && (
                        <p className="text-xs text-rose-500 text-center font-medium">
                          {error}
                        </p>
                      )}
                    </CardContent>

                    <CardFooter className="flex-col gap-2 pt-0">
                      <Button
                        type="submit"
                        className="w-full font-bold h-10"
                        disabled={isLoading || otp.length !== 6}
                      >
                        {isLoading ? (
                          <>
                            <Loader2 className="mr-2 size-4 animate-spin" />
                            Verifying...
                          </>
                        ) : (
                          <>
                            Verify code & Enter Dashboard
                            <ArrowRight className="ml-2 size-4" />
                          </>
                        )}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() => setStep("signIn")}
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
