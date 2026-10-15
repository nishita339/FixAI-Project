/**
 * FixAI Cyber Defense — Web Audio API Sound Synthesizer
 * ======================================================
 * 
 * Improvement #12: Native in-browser tactical audio alerts.
 * Zero external audio files required — 100% synthesized in real-time
 * via Web Audio API oscillators and gain nodes.
 */

class AudioAlertManager {
  private ctx: AudioContext | null = null;
  private isMuted: boolean = false;
  private volume: number = 0.6;

  constructor() {
    if (typeof window !== "undefined") {
      const savedMute = localStorage.getItem("fixai_audio_muted");
      this.isMuted = savedMute === "true";
    }
  }

  private initContext(): AudioContext | null {
    if (typeof window === "undefined") return null;
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume();
    }
    return this.ctx;
  }

  public getMuted(): boolean {
    return this.isMuted;
  }

  public setMuted(muted: boolean): void {
    this.isMuted = muted;
    if (typeof window !== "undefined") {
      localStorage.setItem("fixai_audio_muted", String(muted));
    }
  }

  public toggleMute(): boolean {
    this.setMuted(!this.isMuted);
    if (!this.isMuted) {
      this.playHealedChime();
    }
    return this.isMuted;
  }

  /**
   * Critical Cyber Threat Siren (Alternating high/low warble)
   */
  public playCriticalSiren(): void {
    if (this.isMuted) return;
    const ctx = this.initContext();
    if (!ctx) return;

    try {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      // Modulate frequency like an emergency klaxon
      osc.frequency.linearRampToValueAtTime(1320, ctx.currentTime + 0.15);
      osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.3);
      osc.frequency.linearRampToValueAtTime(1320, ctx.currentTime + 0.45);
      osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.6);

      gain.gain.setValueAtTime(this.volume * 0.4, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.7);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.7);
    } catch {
      // AudioContext policy catch
    }
  }

  /**
   * Warning Double Pulse
   */
  public playWarningBeep(): void {
    if (this.isMuted) return;
    const ctx = this.initContext();
    if (!ctx) return;

    try {
      [0, 0.12].forEach((offset) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = "sine";
        osc.frequency.setValueAtTime(740, ctx.currentTime + offset);

        gain.gain.setValueAtTime(this.volume * 0.35, ctx.currentTime + offset);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + offset + 0.08);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start(ctx.currentTime + offset);
        osc.stop(ctx.currentTime + offset + 0.08);
      });
    } catch {
      // AudioContext policy catch
    }
  }

  /**
   * Pleasant Remediated / Healed Chime (Ascending triad arpeggio)
   */
  public playHealedChime(): void {
    if (this.isMuted) return;
    const ctx = this.initContext();
    if (!ctx) return;

    try {
      // C5 (523Hz), E5 (659Hz), G5 (784Hz), C6 (1046Hz)
      const notes = [523.25, 659.25, 783.99, 1046.5];
      notes.forEach((freq, idx) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        const startTime = ctx.currentTime + idx * 0.08;
        osc.type = "triangle";
        osc.frequency.setValueAtTime(freq, startTime);

        gain.gain.setValueAtTime(this.volume * 0.25, startTime);
        gain.gain.exponentialRampToValueAtTime(0.001, startTime + 0.4);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start(startTime);
        osc.stop(startTime + 0.4);
      });
    } catch {
      // AudioContext policy catch
    }
  }

  /**
   * Emergency Lockdown Engagement Klaxon
   */
  public playLockdownEngagement(): void {
    if (this.isMuted) return;
    const ctx = this.initContext();
    if (!ctx) return;

    try {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(350, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(110, ctx.currentTime + 0.5);

      gain.gain.setValueAtTime(this.volume * 0.5, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.55);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.55);
    } catch {
      // AudioContext policy catch
    }
  }
}

export const audioAlerts = new AudioAlertManager();
