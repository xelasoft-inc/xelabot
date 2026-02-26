import { Page } from 'playwright-core';
import { log } from '../utils';
import * as fs from 'fs';
import * as path from 'path';

/** Embedded Xelasoft logo (dark background) used when vexa-logo-default.png is not found on disk. */
const EMBEDDED_LOGODARK_DATA_URI =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAACfrSURBVHgB7d19zF/neV/wm/AaXhwIZpgUYoYfoHG6JM1WmIJb1kYrplMibeBWWhuSiDZ/pHI9Ia1bRESrThEZf6AhE6q0alO8/We70rI2QNVMSWOqJl2K06yshAfyvsBIzUvsAAaSPdfjOOHFj/38zrnv87vPuT8fyTIhyT/g55zvua7rvu7j3nDJpd9PAEBTXpUAgOYIAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEEnpIm69tpr0/u3bk10s3i4UHnjjTem+xYXE+Px0ksvpQ0bNiS62/q+96Vt27YlxuOdV1+d9u/fnxiHk08+Oe3atSuN2XFvuOTS7yeAJoylsvfEE0+krdddl8bsuDdccun3E0ATxvLyD4888ki69JJLEuMhAABAg7QAAKBBKgAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEECAAA0SAAAgAYJAADQIAEAABokAABAgwQAAGiQAAAADRIAAKBBAgAANEgAAIAGCQAA0CABAAAaJAAAQIMEAABokAAAAA0SAACgQQIAADRIAACABgkAANAgAQAAGiQAAECDBAAAaJAAAAANEgAAoEEnpIm69tpr0/u3bk10s3///pf8WlxcTI9+61vpoaXf46/j79Vg44br0prT1ie6efa5Jw79fvDJ9MILzyz9/kQ68PSj6bvPPLr0+yOJ8VtYWEhvfstb0oaLL17+69NPPz2tW7cusTp3fuxj6c4/+qM0Rce94ZJLv58m6tbbbktvWfqDT3579+5N99x1V7rn7rvTPJ180pnpn1z8vnTC8Scn8np+KRA8/tQD6bHH/zY9tf8rifGIl/w1W7akqzZv9rLvYe/e+9IN2/5dmqpJB4D4g/97f/AHyz8MlPHII48sJ+R5BoHzzrk8rT/v5xPlRGXg/of/6/Lv1C1e/O9+z3s893qKZ9sN27Yt/z5Vx59z9trfThMVZernDh5MP3X55Yky4iGz6ad/erm8+H/uv38urYH93/1mWnP6hcvVAMo44fhT0nlr4+fouPTUga8m6hM/ix/8rd9abn+edNJJiX7u2L59udI5ZZMOAOH+pZfSm3/yJ5XBCnv961+frlgKAvfu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';

/**
 * ScreenContentService
 *
 * Manages a virtual camera feed for the bot by monkey-patching getUserMedia.
 * Instead of using screen share (which doesn't work in Xvfb), we replace
 * the bot's camera feed with a canvas that we can draw images/text onto.
 *
 * How it works:
 * 1. An addInitScript patches navigator.mediaDevices.getUserMedia so that
 *    when Google Meet requests video, it gets a MediaStream from a hidden canvas.
 * 2. The canvas is 1920x1080 and initially shows a black screen.
 * 3. To show an image, we call page.evaluate() to draw it onto the canvas.
 * 4. The canvas.captureStream() automatically updates the video track.
 *
 * This means participants see the bot's "camera" showing our content.
 */
export class ScreenContentService {
  private page: Page;
  private _currentContentType: string | null = null;
  private _currentUrl: string | null = null;
  private _initialized: boolean = false;

  // Default avatar: Xelasoft logo (small, centered on black background)
  // Can be overridden via setAvatar() API
  private _defaultAvatarDataUri: string | null = null;
  private _customAvatarDataUri: string | null = null;

  constructor(page: Page, defaultAvatarUrl?: string) {
    this.page = page;
    // If a custom default avatar URL was provided via bot config, use it
    if (defaultAvatarUrl) {
      this._customAvatarDataUri = defaultAvatarUrl;
      log(`[ScreenContent] Custom default avatar URL set from config: ${defaultAvatarUrl.substring(0, 80)}...`);
    }
    // Load the built-in Xelasoft logo as fallback
    this._loadDefaultAvatar();
  }

  private _loadDefaultAvatar(): void {
    try {
      // Try multiple paths (dev vs Docker). The repository currently ships
      // vexa-logo-default.png; keep vexa-logo-light.png as a legacy fallback.
      const possiblePaths = [
        path.join(__dirname, '../../assets/vexa-logo-default.png'),
        path.join(__dirname, '../assets/vexa-logo-default.png'),
        path.join(__dirname, '../../assets/vexa-logo-light.png'),
        path.join(__dirname, '../assets/vexa-logo-light.png'),
        '/app/assets/vexa-logo-default.png',
        '/app/assets/vexa-logo-light.png',
      ];
      for (const p of possiblePaths) {
        if (fs.existsSync(p)) {
          const buf = fs.readFileSync(p);
          this._defaultAvatarDataUri = `data:image/png;base64,${buf.toString('base64')}`;
          log(`[ScreenContent] Default avatar loaded from ${p} (${buf.length} bytes)`);
          return;
        }
      }
      // No PNG found: use embedded Xelasoft logo so we never show the text placeholder
      this._defaultAvatarDataUri = EMBEDDED_LOGODARK_DATA_URI;
      log('[ScreenContent] Default avatar: using embedded Xelasoft logo (no logo PNG found on disk)');
    } catch (err: any) {
      log(`[ScreenContent] Failed to load default avatar: ${err.message}`);
      this._defaultAvatarDataUri = EMBEDDED_LOGODARK_DATA_URI;
    }
  }

  /**
   * Get the current avatar data URI (custom or default).
   */
  private _getAvatarDataUri(): string | null {
    return this._customAvatarDataUri || this._defaultAvatarDataUri;
  }

  /**
   * Initialize the virtual canvas camera.
   * Must be called AFTER the page has navigated to Google Meet.
   * The canvas and stream are already created by the init script — this
   * just verifies they exist and are usable.
   */
  async initialize(): Promise<void> {
    if (this._initialized) return;

    // The init script (getVirtualCameraInitScript) already created the canvas,
    // ctx, and stream. Verify they're present.
    const status = await this.page.evaluate(() => {
      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      const stream = (window as any).__vexa_canvas_stream as MediaStream;
      return {
        hasCanvas: !!canvas,
        hasCtx: !!ctx,
        hasStream: !!stream,
        videoTracks: stream ? stream.getVideoTracks().length : 0,
      };
    });

    if (!status.hasCanvas || !status.hasCtx || !status.hasStream) {
      // Init script didn't run yet or failed — create canvas now as fallback
      log('[ScreenContent] Init script canvas not found, creating fallback canvas...');
      await this.page.evaluate(() => {
        if ((window as any).__vexa_canvas) return; // already exists

        const canvas = document.createElement('canvas');
        canvas.id = '__vexa_screen_canvas';
        canvas.width = 1920;
        canvas.height = 1080;
        canvas.style.position = 'fixed';
        canvas.style.top = '-9999px';
        canvas.style.left = '-9999px';
        document.body.appendChild(canvas);

        const ctx = canvas.getContext('2d')!;
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, 1920, 1080);

        const stream = canvas.captureStream(30);

        (window as any).__vexa_canvas = canvas;
        (window as any).__vexa_canvas_ctx = ctx;
        (window as any).__vexa_canvas_stream = stream;
      });
    }

    this._initialized = true;
    log(`[ScreenContent] Canvas virtual camera initialized (initScript canvas: ${status.hasCanvas}, tracks: ${status.videoTracks})`);

    // Draw the default avatar on the canvas (replaces the init script placeholder)
    const avatarUri = this._getAvatarDataUri();
    if (avatarUri) {
      await this._drawAvatarOnCanvas(avatarUri);
      log('[ScreenContent] Default avatar drawn on canvas');
    }

    // Start the frame pump — captureStream(30) only emits frames when the
    // canvas changes. This loop makes an invisible 1-pixel change on every
    // animation frame to keep the stream alive.
    await this._startFramePump();
  }

  /**
   * Start a requestAnimationFrame loop that touches a single pixel on
   * each frame, forcing captureStream(30) to continuously emit frames.
   * Without this, static content (avatar, images) produces only 1-2 frames
   * and Google Meet stops displaying the video feed.
   */
  private async _startFramePump(): Promise<void> {
    await this.page.evaluate(() => {
      // Don't start twice
      if ((window as any).__vexa_frame_pump_active) return;
      (window as any).__vexa_frame_pump_active = true;

      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      if (!canvas || !ctx) return;

      // Continuously "touch" the canvas to force captureStream to emit frames.
      // We read+write a single pixel at (0,0) — this triggers a change event
      // without any visible effect on the content.
      let toggle = false;
      const pump = () => {
        if (!(window as any).__vexa_frame_pump_active) return;

        // Alternate between two invisible operations to ensure the canvas
        // is always "dirty" from captureStream's perspective.
        try {
          const pixel = ctx.getImageData(0, 0, 1, 1);
          // Flip the alpha by 1 unit (invisible at these values)
          pixel.data[3] = toggle ? 254 : 255;
          toggle = !toggle;
          ctx.putImageData(pixel, 0, 0);
        } catch {}

        requestAnimationFrame(pump);
      };
      requestAnimationFrame(pump);
      console.log('[Vexa] Frame pump started for continuous captureStream output');
    });
    log('[ScreenContent] Frame pump started');
  }

  /**
   * Teams light-meetings may expose only "Open video options". Try selecting
   * a camera device there, then use the Teams keyboard shortcut for video.
   */
  private async tryTeamsVideoOptionsFallback(): Promise<boolean> {
    const videoOptionsBtn = this.page.locator([
      'button[aria-label="Open video options"]',
      'button[aria-label="open video options"]',
      'button[aria-label="Video options"]',
      'button[aria-label="video options"]',
      'button[aria-label="Camera options"]',
      'button[aria-label="camera options"]',
      'button:has-text("Open video options")',
    ].join(', ')).first();

    const optionsVisible = await videoOptionsBtn.isVisible().catch(() => false);
    if (!optionsVisible) return false;

    try {
      const label = await videoOptionsBtn.getAttribute('aria-label');
      await videoOptionsBtn.click({ force: true });
      log(`[ScreenContent] Opened video options${label ? ` ("${label}")` : ''}`);
      await this.page.waitForTimeout(700);
    } catch (err: any) {
      log(`[ScreenContent] Failed to open video options: ${err.message}`);
      return false;
    }

    let deviceSelected = false;

    const vexaOption = this.page.locator([
      '[role="menuitemradio"]:has-text("Vexa Virtual Camera")',
      '[role="option"]:has-text("Vexa Virtual Camera")',
      'button:has-text("Vexa Virtual Camera")',
      '[data-tid*="camera"]:has-text("Vexa Virtual Camera")',
      'span:has-text("Vexa Virtual Camera")',
    ].join(', ')).first();
    try {
      const vexaVisible = await vexaOption.isVisible().catch(() => false);
      if (vexaVisible) {
        await vexaOption.click({ force: true });
        deviceSelected = true;
        log('[ScreenContent] Selected "Vexa Virtual Camera" in video options');
      }
    } catch {}

    if (!deviceSelected) {
      const fallbackCameraLabel = await this.page.evaluate(() => {
        const normalize = (value: string | null | undefined): string =>
          (value || '').replace(/\s+/g, ' ').trim();
        const isVisible = (el: Element): boolean => {
          const node = el as HTMLElement;
          const style = window.getComputedStyle(node);
          const rect = node.getBoundingClientRect();
          return (
            rect.width > 0 &&
            rect.height > 0 &&
            style.visibility !== 'hidden' &&
            style.display !== 'none'
          );
        };
        const candidates = Array.from(
          document.querySelectorAll('[role="menuitemradio"], [role="option"], button, [data-tid], [aria-label]')
        );
        for (const el of candidates) {
          if (!isVisible(el)) continue;
          const label = normalize((el as HTMLElement).innerText || el.getAttribute('aria-label'));
          if (!label) continue;
          const lower = label.toLowerCase();
          const isCameraDeviceCandidate =
            lower.includes('camera') &&
            !lower.includes('open video options') &&
            !lower.includes('video options') &&
            !lower.includes('turn on camera') &&
            !lower.includes('turn off camera') &&
            !lower.includes('turn camera on') &&
            !lower.includes('turn camera off') &&
            !lower.includes('turn on video') &&
            !lower.includes('turn off video') &&
            !lower.includes('no camera');
          if (!isCameraDeviceCandidate) continue;
          (el as HTMLElement).click();
          return label;
        }
        return null;
      });

      if (fallbackCameraLabel) {
        deviceSelected = true;
        log(`[ScreenContent] Selected fallback camera option: "${fallbackCameraLabel}"`);
      } else {
        log('[ScreenContent] No selectable camera device found in video options');
      }
    }

    await this.page.keyboard.press('Escape').catch(() => {});
    await this.page.waitForTimeout(500);

    await this.page.keyboard.press('Control+Shift+O').catch(() => {});
    await this.page.waitForTimeout(1000);

    const turnOffVisible = await this.page.locator([
      'button[aria-label="Turn off camera"]',
      'button[aria-label="turn off camera"]',
      'button[aria-label="Turn camera off"]',
      'button[aria-label="turn camera off"]',
      'button[aria-label="Turn off video"]',
      'button[aria-label="turn off video"]',
    ].join(', ')).first().isVisible().catch(() => false);

    if (turnOffVisible) {
      log('[ScreenContent] Video options fallback succeeded; camera appears ON');
      return true;
    }

    log('[ScreenContent] Video options fallback did not expose a camera-ON state');
    return deviceSelected;
  }

  /**
   * Turn on the camera/video button if it's off.
   * Works for both Google Meet ("Turn on camera") and Teams ("Turn on video").
   * The getUserMedia patch ensures that when the platform gets the camera stream,
   * it receives our canvas stream. So just clicking the button is enough.
   */
  async enableCamera(): Promise<void> {
    if (!this._initialized) await this.initialize();

    // First, log all toolbar buttons for diagnostics
    const toolbarButtons = await this.page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons
        .filter(b => {
          const rect = b.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        })
        .map(b => ({
          ariaLabel: b.getAttribute('aria-label') || '',
          tooltip: b.getAttribute('data-tooltip') || '',
        }))
        .filter(b =>
          b.ariaLabel.toLowerCase().includes('camera') ||
          b.ariaLabel.toLowerCase().includes('video') ||
          b.ariaLabel.toLowerCase().includes('камер') ||
          b.tooltip.toLowerCase().includes('camera') ||
          b.tooltip.toLowerCase().includes('video')
        );
    });
    log(`[ScreenContent] Camera-related buttons: ${JSON.stringify(toolbarButtons)}`);

    // Click "Turn on camera/video" if it's visible (means camera is currently off)
    // Includes both Google Meet ("camera") and Teams ("video"/"camera") selectors
    // NOTE: Teams has "Open video options" which also contains "video" — we must
    // use specific prefixes to avoid matching the wrong button.
    // Teams uses BOTH "Turn camera on" and "Turn on camera" depending on version.
    const turnOnCameraBtn = this.page.locator([
      // Google Meet selectors
      'button[aria-label="Turn on camera"]',
      'button[aria-label="turn on camera"]',
      'button[aria-label="Включить камеру"]',
      'button[data-tooltip="Turn on camera"]',
      // Teams selectors — multiple aria-label variants
      'button[aria-label="Turn on video"]',
      'button[aria-label="turn on video"]',
      'button[aria-label="Turn camera on"]',
      'button[aria-label="turn camera on"]',
    ].join(', ')).first();

    try {
      await turnOnCameraBtn.waitFor({ state: 'visible', timeout: 5000 });
      const label = await turnOnCameraBtn.getAttribute('aria-label');
      log(`[ScreenContent] Found camera/video button: "${label}", clicking...`);
      await turnOnCameraBtn.click({ force: true });
      log('[ScreenContent] Clicked camera/video button — getUserMedia patch will provide canvas stream');
      // Wait for camera to initialize and getUserMedia to be called
      await this.page.waitForTimeout(3000);
    } catch {
      log('[ScreenContent] Camera/video button not found — trying "Turn off" check (maybe already on)');
      // Check if camera is already on
      const turnOffCameraBtn = this.page.locator([
        'button[aria-label="Turn off camera"]',
        'button[aria-label="turn off camera"]',
        'button[aria-label="Выключить камеру"]',
        // Teams — multiple variants
        'button[aria-label="Turn off video"]',
        'button[aria-label="turn off video"]',
        'button[aria-label="Turn camera off"]',
        'button[aria-label="turn camera off"]',
      ].join(', ')).first();
      try {
        await turnOffCameraBtn.waitFor({ state: 'visible', timeout: 2000 });
        log('[ScreenContent] Camera/video is already ON (found "Turn off" button)');
      } catch {
        log('[ScreenContent] Neither camera/video on nor off button found — trying video options fallback');
        const fallbackEnabled = await this.tryTeamsVideoOptionsFallback();
        if (!fallbackEnabled) {
          log('[ScreenContent] Video options fallback unavailable or unsuccessful');
        }
      }
    }

    // Diagnostic: check if our canvas track is being sent via WebRTC
    const diagnostic = await this.page.evaluate(() => {
      const pcs = (window as any).__vexa_peer_connections as RTCPeerConnection[] || [];
      const canvasStream = (window as any).__vexa_canvas_stream as MediaStream;
      const canvasTrackId = canvasStream?.getVideoTracks()[0]?.id || 'none';
      const info: any[] = [];

      for (let i = 0; i < pcs.length; i++) {
        const pc = pcs[i];
        if (pc.connectionState === 'closed') continue;
        const senders = pc.getSenders();
        for (const s of senders) {
          if (s.track && s.track.kind === 'video') {
            info.push({
              pc: i,
              trackId: s.track.id,
              isCanvasTrack: s.track.id === canvasTrackId,
              trackLabel: s.track.label,
              enabled: s.track.enabled,
              readyState: s.track.readyState,
            });
          }
        }
      }

      // Also check transceivers for video slots
      const transceiverInfo: any[] = [];
      for (let i = 0; i < pcs.length; i++) {
        const pc = pcs[i];
        if (pc.connectionState === 'closed') continue;
        try {
          for (const t of pc.getTransceivers()) {
            if (t.sender && (
              t.receiver?.track?.kind === 'video' ||
              (t.sender.track && t.sender.track.kind === 'video') ||
              (t.mid && t.mid.includes('video'))
            )) {
              transceiverInfo.push({
                pc: i,
                mid: t.mid,
                senderTrackId: t.sender.track?.id || 'null',
                isCanvasTrack: t.sender.track?.id === canvasTrackId,
                direction: t.direction,
              });
            }
          }
        } catch {}
      }

      return {
        canvasTrackId,
        peerConnections: pcs.length,
        videoSenders: info,
        videoTransceivers: transceiverInfo,
        gumCallCount: (window as any).__vexa_gum_call_count || 0,
        gumVideoIntercepted: (window as any).__vexa_gum_video_intercepted || 0,
        addTrackIntercepted: (window as any).__vexa_addtrack_intercepted || 0,
      };
    });
    log(`[ScreenContent] Camera diagnostic: ${JSON.stringify(diagnostic)}`);

    // Always try replaceTrack to ensure our canvas is the active video source.
    // --use-fake-ui-for-media-stream bypasses our getUserMedia JS patch, so
    // Chromium provides fake device video at a lower level. We need replaceTrack
    // to swap the fake/null track for our canvas track.
    log('[ScreenContent] Attempting replaceTrack to inject canvas stream into WebRTC...');
    const replaceResult = await this.page.evaluate(async () => {
      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      if (!canvas) return { success: false, reason: 'no canvas' };

      // "Touch" the canvas to force captureStream to generate a new frame.
      // captureStream(30) only emits frames when canvas content changes.
      // Drawing a tiny invisible pixel forces a change event.
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      if (ctx) {
        // Read then write a single pixel at (0,0) — triggers frame without visual change
        const pixel = ctx.getImageData(0, 0, 1, 1);
        ctx.putImageData(pixel, 0, 0);
      }

      // Always create a fresh captureStream to get a live track.
      // Google Meet's camera toggle can kill previous tracks.
      const freshStream = canvas.captureStream(30);
      (window as any).__vexa_canvas_stream = freshStream;
      const canvasTrack = freshStream.getVideoTracks()[0];
      if (!canvasTrack) return { success: false, reason: 'failed to get canvas track from fresh stream' };
      console.log('[Vexa] Fresh canvas track created: id=' + canvasTrack.id + ' readyState=' + canvasTrack.readyState);

      const pcs = (window as any).__vexa_peer_connections as RTCPeerConnection[] || [];
      let replaced = 0;
      const details: string[] = [];
      const errors: string[] = [];

      for (let i = 0; i < pcs.length; i++) {
        const pc = pcs[i];
        if (pc.connectionState === 'closed') continue;
        try {
          const transceivers = pc.getTransceivers();
          for (const t of transceivers) {
            // Only replace on sendonly or sendrecv transceivers with video capability
            const isSendVideo =
              (t.direction === 'sendonly' || t.direction === 'sendrecv') &&
              (t.sender !== null) &&
              // Check if this transceiver handles video
              (t.receiver?.track?.kind === 'video' ||
               (t.sender.track && t.sender.track.kind === 'video') ||
               // Also match transceivers with null sender track (camera off/fake device)
               (t.sender.track === null && t.direction === 'sendonly'));

            if (isSendVideo) {
              try {
                await t.sender.replaceTrack(canvasTrack);
                replaced++;
                details.push('pc' + i + ':mid=' + t.mid + ':dir=' + t.direction);
              } catch (e: any) {
                errors.push('pc' + i + ':mid=' + t.mid + ':' + e.message);
              }
            }
          }
        } catch (e: any) {
          errors.push('pc' + i + ':getTransceivers:' + e.message);
        }

        // Fallback: also try senders directly
        if (replaced === 0) {
          const senders = pc.getSenders();
          for (const s of senders) {
            if (s.track === null || (s.track && s.track.kind === 'video')) {
              try {
                await s.replaceTrack(canvasTrack);
                replaced++;
                details.push('pc' + i + ':sender(trackWas=' + (s.track?.kind || 'null') + ')');
              } catch (e: any) {
                errors.push('pc' + i + ':sender:' + e.message);
              }
            }
          }
        }
      }

      // Verify the replacement
      const verification: any[] = [];
      for (let i = 0; i < pcs.length; i++) {
        const pc = pcs[i];
        if (pc.connectionState === 'closed') continue;
        for (const s of pc.getSenders()) {
          if (s.track && s.track.kind === 'video') {
            verification.push({
              pc: i,
              trackId: s.track.id,
              isCanvas: s.track.id === canvasTrack.id,
              label: s.track.label,
              enabled: s.track.enabled,
              readyState: s.track.readyState,
            });
          }
        }
      }

      return {
        success: replaced > 0,
        replaced,
        details: details.join(', '),
        errors: errors.length > 0 ? errors.join(', ') : undefined,
        verification,
      };
    });
    log(`[ScreenContent] replaceTrack result: ${JSON.stringify(replaceResult)}`);

    // Deep WebRTC SDP diagnostic — check what the SDP says about video
    const sdpDiag = await this.page.evaluate(async () => {
      const pcs = (window as any).__vexa_peer_connections as RTCPeerConnection[] || [];
      const results: any[] = [];
      for (let i = 0; i < pcs.length; i++) {
        const pc = pcs[i];
        if (pc.connectionState === 'closed') continue;
        const localDesc = pc.localDescription;
        const remoteDesc = pc.remoteDescription;

        // Parse video m= lines from SDP
        const parseVideoLines = (sdp: string | null | undefined) => {
          if (!sdp) return null;
          const lines = sdp.split('\n');
          const videoSections: string[] = [];
          let inVideo = false;
          let current = '';
          for (const line of lines) {
            if (line.startsWith('m=video')) {
              inVideo = true;
              current = line.trim();
            } else if (line.startsWith('m=') && inVideo) {
              videoSections.push(current);
              inVideo = false;
              current = '';
            } else if (inVideo) {
              // Only capture key lines: a=mid, a=sendonly, a=recvonly, a=inactive, a=msid, a=ssrc
              const trimmed = line.trim();
              if (trimmed.startsWith('a=mid:') || trimmed.startsWith('a=sendonly') ||
                  trimmed.startsWith('a=recvonly') || trimmed.startsWith('a=inactive') ||
                  trimmed.startsWith('a=sendrecv') || trimmed.startsWith('a=msid:') ||
                  trimmed.startsWith('a=ssrc:') || trimmed.startsWith('a=extmap-allow-mixed') ||
                  trimmed.startsWith('c=')) {
                current += ' | ' + trimmed;
              }
            }
          }
          if (current) videoSections.push(current);
          return videoSections;
        };

        // Also get sender track info AFTER replaceTrack
        const senderInfo: any[] = [];
        for (const s of pc.getSenders()) {
          senderInfo.push({
            trackKind: s.track?.kind || 'null',
            trackId: s.track?.id?.substring(0, 16) || 'null',
            trackLabel: s.track?.label?.substring(0, 40) || 'null',
            trackReadyState: s.track?.readyState || 'null',
            trackEnabled: s.track?.enabled ?? null,
          });
        }

        // getStats for outbound video
        let outboundVideoStats: any = null;
        try {
          const stats = await pc.getStats();
          stats.forEach((report: any) => {
            if (report.type === 'outbound-rtp' && report.kind === 'video') {
              outboundVideoStats = {
                bytesSent: report.bytesSent,
                packetsSent: report.packetsSent,
                framesSent: report.framesSent,
                framesEncoded: report.framesEncoded,
                frameWidth: report.frameWidth,
                frameHeight: report.frameHeight,
                framesPerSecond: report.framesPerSecond,
                qualityLimitationReason: report.qualityLimitationReason,
                active: report.active,
              };
            }
          });
        } catch {}

        results.push({
          pc: i,
          connectionState: pc.connectionState,
          iceConnectionState: pc.iceConnectionState,
          signalingState: pc.signalingState,
          localVideoSDP: parseVideoLines(localDesc?.sdp),
          remoteVideoSDP: parseVideoLines(remoteDesc?.sdp),
          senders: senderInfo,
          outboundVideoStats,
        });
      }
      return results;
    });
    log(`[ScreenContent] SDP diagnostic: ${JSON.stringify(sdpDiag)}`);
  }

  /**
   * Toggle camera off→on to force Teams SDP renegotiation.
   *
   * Teams "light meetings" (anonymous/guest) sometimes sets video to `inactive`
   * in the initial SDP answer, making all replaceTrack attempts useless.
   * Toggling the camera UI off then on forces Teams to renegotiate the SDP
   * with video enabled, allowing the virtual camera stream to flow.
   */
  async toggleCameraForRenegotiation(): Promise<boolean> {
    log('[ScreenContent] Attempting camera toggle (off→on) to force SDP renegotiation...');

    // All known "camera/video off" button selectors for Teams + Meet
    const turnOffSelectors = [
      'button[aria-label="Turn off camera"]',
      'button[aria-label="turn off camera"]',
      'button[aria-label="Turn camera off"]',
      'button[aria-label="turn camera off"]',
      'button[aria-label="Turn off video"]',
      'button[aria-label="turn off video"]',
      'button[aria-label="Выключить камеру"]',
    ];

    const turnOnSelectors = [
      'button[aria-label="Turn on camera"]',
      'button[aria-label="turn on camera"]',
      'button[aria-label="Turn camera on"]',
      'button[aria-label="turn camera on"]',
      'button[aria-label="Turn on video"]',
      'button[aria-label="turn on video"]',
      'button[aria-label="Включить камеру"]',
    ];

    try {
      // Step 1: Turn camera OFF
      const turnOffBtn = this.page.locator(turnOffSelectors.join(', ')).first();
      try {
        await turnOffBtn.waitFor({ state: 'visible', timeout: 3000 });
        const label = await turnOffBtn.getAttribute('aria-label');
        log(`[ScreenContent] Toggle: clicking OFF button ("${label}")...`);
        await turnOffBtn.click({ force: true });
        // Wait for Teams to process the camera-off and release the video track
        await this.page.waitForTimeout(2000);
      } catch {
        // Camera might already be off — try turning it on directly
        log('[ScreenContent] Toggle: no "turn off" button found — camera may already be off');
      }

      // Step 2: Turn camera ON (this triggers getUserMedia → our canvas track → SDP renegotiation)
      const turnOnBtn = this.page.locator(turnOnSelectors.join(', ')).first();
      try {
        await turnOnBtn.waitFor({ state: 'visible', timeout: 3000 });
        const label = await turnOnBtn.getAttribute('aria-label');
        log(`[ScreenContent] Toggle: clicking ON button ("${label}")...`);
        await turnOnBtn.click({ force: true });
        // Wait for getUserMedia, replaceTrack, and SDP renegotiation
        await this.page.waitForTimeout(3000);
        log('[ScreenContent] Toggle: camera toggled on — SDP renegotiation should be in progress');

        // Now run replaceTrack to ensure our canvas stream is the active video source
        await this.enableCamera();
        return true;
      } catch {
        log('[ScreenContent] Toggle: no "turn on" button found — trying video options fallback');
        const fallbackEnabled = await this.tryTeamsVideoOptionsFallback();
        if (fallbackEnabled) {
          await this.enableCamera();
          return true;
        }
        log('[ScreenContent] Toggle: video options fallback failed');
        return false;
      }
    } catch (err: any) {
      log(`[ScreenContent] Toggle failed: ${err.message}`);
      return false;
    }
  }

  /**
   * Display an image on the virtual camera feed.
   * @param imageSource URL or base64 data URI for the image
   */
  async showImage(imageSource: string): Promise<void> {
    if (!this._initialized) await this.initialize();

    // Handle base64 images
    let src = imageSource;
    if (!imageSource.startsWith('http') && !imageSource.startsWith('data:')) {
      src = `data:image/png;base64,${imageSource}`;
    }

    // Draw the image onto the canvas
    const success = await this.page.evaluate(async (imgSrc: string) => {
      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      if (!canvas || !ctx) return false;

      return new Promise<boolean>((resolve) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => {
          // Clear canvas to black
          ctx.fillStyle = '#000000';
          ctx.fillRect(0, 0, canvas.width, canvas.height);

          // Calculate centered fit (contain)
          const scale = Math.min(canvas.width / img.width, canvas.height / img.height);
          const w = img.width * scale;
          const h = img.height * scale;
          const x = (canvas.width - w) / 2;
          const y = (canvas.height - h) / 2;

          ctx.drawImage(img, x, y, w, h);
          resolve(true);
        };
        img.onerror = () => {
          // Draw error text
          ctx.fillStyle = '#000000';
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.fillStyle = '#ff0000';
          ctx.font = '48px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText('Failed to load image', canvas.width / 2, canvas.height / 2);
          resolve(false);
        };
        img.src = imgSrc;
      });
    }, src);

    if (success) {
      this._currentContentType = 'image';
      this._currentUrl = imageSource;
      log(`[ScreenContent] Showing image on virtual camera: ${imageSource.substring(0, 80)}...`);
    } else {
      log(`[ScreenContent] Failed to load image: ${imageSource.substring(0, 80)}...`);
    }

    // Enable camera if not already
    await this.enableCamera();
  }

  /**
   * Display custom HTML-rendered content.
   * For now, just show text on the canvas.
   */
  async showText(text: string, fontSize: number = 48): Promise<void> {
    if (!this._initialized) await this.initialize();

    await this.page.evaluate(({ text, fontSize }: { text: string; fontSize: number }) => {
      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      if (!canvas || !ctx) return;

      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#ffffff';
      ctx.font = `${fontSize}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Word wrap
      const maxWidth = canvas.width - 100;
      const words = text.split(' ');
      const lines: string[] = [];
      let currentLine = words[0];

      for (let i = 1; i < words.length; i++) {
        const testLine = currentLine + ' ' + words[i];
        const metrics = ctx.measureText(testLine);
        if (metrics.width > maxWidth) {
          lines.push(currentLine);
          currentLine = words[i];
        } else {
          currentLine = testLine;
        }
      }
      lines.push(currentLine);

      const lineHeight = fontSize * 1.3;
      const totalHeight = lines.length * lineHeight;
      const startY = (canvas.height - totalHeight) / 2 + fontSize / 2;

      for (let i = 0; i < lines.length; i++) {
        ctx.fillText(lines[i], canvas.width / 2, startY + i * lineHeight);
      }
    }, { text, fontSize });

    this._currentContentType = 'text';
    this._currentUrl = null;
    log(`[ScreenContent] Showing text on virtual camera: "${text.substring(0, 50)}..."`);

    await this.enableCamera();
  }

  /**
   * Clear the canvas — reverts to showing the default avatar (Vexa logo).
   * If no avatar is available, shows black.
   */
  async clearScreen(): Promise<void> {
    if (!this._initialized) return;

    // Try to show the avatar instead of a plain black screen
    const avatarUri = this._getAvatarDataUri();
    if (avatarUri) {
      await this._drawAvatarOnCanvas(avatarUri);
    } else {
      await this.page.evaluate(() => {
        const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
        const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
        if (!canvas || !ctx) return;

        // Dark branded background when no avatar is available
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      });
    }

    this._currentContentType = null;
    this._currentUrl = null;
    log('[ScreenContent] Screen cleared (showing default avatar)');
  }

  /**
   * Set a custom avatar image (replaces the default Vexa logo).
   * @param imageSource URL or base64 data URI of the avatar image
   */
  async setAvatar(imageSource: string): Promise<void> {
    let src = imageSource;
    if (!imageSource.startsWith('http') && !imageSource.startsWith('data:')) {
      src = `data:image/png;base64,${imageSource}`;
    }
    this._customAvatarDataUri = src;
    log(`[ScreenContent] Custom avatar set: ${src.substring(0, 60)}...`);

    // If currently showing avatar (no active content), refresh the display
    if (!this._currentContentType && this._initialized) {
      await this._drawAvatarOnCanvas(src);
    }
  }

  /**
   * Reset avatar to the default Vexa logo.
   */
  async resetAvatar(): Promise<void> {
    this._customAvatarDataUri = null;
    log('[ScreenContent] Avatar reset to default');

    // If currently showing avatar (no active content), refresh the display
    if (!this._currentContentType && this._initialized) {
      const avatarUri = this._getAvatarDataUri();
      if (avatarUri) {
        await this._drawAvatarOnCanvas(avatarUri);
      }
    }
  }

  /**
   * Draw an avatar image centered on a black background.
   * The logo is drawn small (~12% of canvas height) and centered.
   */
  private async _drawAvatarOnCanvas(avatarUri: string): Promise<void> {
    await this.page.evaluate(async (imgSrc: string) => {
      const canvas = (window as any).__vexa_canvas as HTMLCanvasElement;
      const ctx = (window as any).__vexa_canvas_ctx as CanvasRenderingContext2D;
      if (!canvas || !ctx) return;

      return new Promise<void>((resolve) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => {
          // Black background
          ctx.fillStyle = '#000000';
          ctx.fillRect(0, 0, canvas.width, canvas.height);

          // Draw the logo small and centered (~12% of canvas height)
          const maxSize = Math.max(Math.round(canvas.height * 0.12), 100);
          const scale = Math.min(maxSize / img.width, maxSize / img.height);
          const w = img.width * scale;
          const h = img.height * scale;
          const x = (canvas.width - w) / 2;
          const y = (canvas.height - h) / 2;

          ctx.drawImage(img, x, y, w, h);
          resolve();
        };
        img.onerror = () => {
          // Image failed to load: show black only (never show text placeholder)
          ctx.fillStyle = '#000000';
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          resolve();
        };
        img.src = imgSrc;
      });
    }, avatarUri);
  }

  /**
   * Close / cleanup.
   */
  async close(): Promise<void> {
    this._currentContentType = null;
    this._currentUrl = null;
    this._initialized = false;
    log('[ScreenContent] Content service closed');
  }

  /**
   * Get current display status.
   */
  getStatus(): { hasContent: boolean; contentType: string | null; url: string | null } {
    return {
      hasContent: this._currentContentType !== null,
      contentType: this._currentContentType,
      url: this._currentUrl
    };
  }
}

/**
 * Get the addInitScript code that monkey-patches getUserMedia and RTCPeerConnection.
 * This MUST be injected BEFORE the page navigates to Google Meet.
 *
 * It intercepts:
 * 1. getUserMedia — when video is requested, returns a canvas-based stream
 *    instead of the real camera, so Google Meet uses our canvas from the start.
 * 2. RTCPeerConnection — tracks all connections so we can inspect video senders.
 *
 * The canvas is created eagerly (before getUserMedia is called) and shared
 * between the init script and ScreenContentService.
 */
export function getVirtualCameraInitScript(): string {
  return `
    (() => {
      console.log('[Vexa] Virtual camera init script START in: ' + window.location.href);
      try {
      // ===== 1. Create the canvas and stream eagerly =====
      // We create a 1920x1080 canvas and captureStream(30) immediately.
      // ScreenContentService.initialize() will find these globals and reuse them.
      const canvas = document.createElement('canvas');
      canvas.id = '__vexa_screen_canvas';
      canvas.width = 1920;
      canvas.height = 1080;
      canvas.style.position = 'fixed';
      canvas.style.top = '-9999px';
      canvas.style.left = '-9999px';

      const ctx = canvas.getContext('2d');
      if (ctx) {
        // Initial frame: black only. ScreenContentService.initialize() will draw the logo.
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, 1920, 1080);
      }

      const canvasStream = canvas.captureStream(30);

      // Store globally for ScreenContentService to use
      window.__vexa_canvas = canvas;
      window.__vexa_canvas_ctx = ctx;
      window.__vexa_canvas_stream = canvasStream;

      // Counters for diagnostics
      window.__vexa_gum_call_count = 0;
      window.__vexa_gum_video_intercepted = 0;

      // Append canvas to body when DOM is ready
      const appendCanvas = () => {
        if (document.body) {
          document.body.appendChild(canvas);
        } else {
          document.addEventListener('DOMContentLoaded', () => {
            document.body.appendChild(canvas);
          });
        }
      };
      appendCanvas();

      // ===== 2. Patch getUserMedia =====
      // When Google Meet calls getUserMedia({video: true, audio: true}),
      // we return our canvas video track + the real audio track.
      // This means Meet uses our canvas as the "camera" from the very start.
      const origGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);

      navigator.mediaDevices.getUserMedia = async function(constraints) {
        window.__vexa_gum_call_count = (window.__vexa_gum_call_count || 0) + 1;
        console.log('[Vexa] getUserMedia called with:', JSON.stringify(constraints));

        const wantsVideo = !!(constraints && constraints.video);
        const wantsAudio = !!(constraints && constraints.audio);

        if (wantsVideo) {
          window.__vexa_gum_video_intercepted = (window.__vexa_gum_video_intercepted || 0) + 1;
          console.log('[Vexa] Intercepting video — returning canvas stream');

          // Get canvas video track from the GLOBAL (may have been refreshed by enableCamera)
          const currentStream = window.__vexa_canvas_stream || canvasStream;
          const canvasVideoTrack = currentStream.getVideoTracks()[0];

          if (wantsAudio) {
            // Need both video (from canvas) and audio (real mic)
            try {
              const audioStream = await origGetUserMedia({ audio: constraints.audio });
              const combinedStream = new MediaStream();
              combinedStream.addTrack(canvasVideoTrack.clone());
              for (const audioTrack of audioStream.getAudioTracks()) {
                combinedStream.addTrack(audioTrack);
              }
              console.log('[Vexa] Returning combined stream: canvas video + real audio');
              return combinedStream;
            } catch (audioErr) {
              // If audio fails, return just the canvas video
              console.warn('[Vexa] Audio getUserMedia failed, returning canvas video only:', audioErr);
              const videoOnlyStream = new MediaStream();
              videoOnlyStream.addTrack(canvasVideoTrack.clone());
              return videoOnlyStream;
            }
          } else {
            // Video only request — return canvas stream
            const videoOnlyStream = new MediaStream();
            videoOnlyStream.addTrack(canvasVideoTrack.clone());
            console.log('[Vexa] Returning canvas video only stream');
            return videoOnlyStream;
          }
        }

        // Audio-only or other requests — pass through to original
        return origGetUserMedia(constraints);
      };

      // ===== 3. Patch RTCPeerConnection =====
      // Track all connections AND intercept addTrack to swap video tracks.
      window.__vexa_peer_connections = [];
      window.__vexa_addtrack_intercepted = 0;
      window.__vexa_offer_video_forced = 0;
      const OrigRTC = window.RTCPeerConnection;

      // Patch addTrack on the prototype BEFORE creating any instances.
      // When Google Meet calls pc.addTrack(videoTrack, stream), we swap
      // the video track for our canvas track. This is the most reliable
      // interception point — it catches the track at the exact moment
      // it enters the WebRTC pipeline.
      const origAddTrack = OrigRTC.prototype.addTrack;
      OrigRTC.prototype.addTrack = function(track, ...streams) {
        // IMPORTANT: Read from window.__vexa_canvas_stream (the GLOBAL), not the
        // closure variable. enableCamera() may create a fresh captureStream(30)
        // with a new track ID, and we need to use whatever is current.
        const currentStream = window.__vexa_canvas_stream;
        if (track && track.kind === 'video' && currentStream) {
          const canvasTrack = currentStream.getVideoTracks()[0];
          if (canvasTrack) {
            window.__vexa_addtrack_intercepted = (window.__vexa_addtrack_intercepted || 0) + 1;
            console.log('[Vexa] addTrack intercepted: swapping video track for canvas track (original: ' + track.label + ')');
            return origAddTrack.call(this, canvasTrack, ...streams);
          }
        }
        return origAddTrack.call(this, track, ...streams);
      };

      // Also patch replaceTrack on RTCRtpSender to intercept any later
      // track swaps that Google Meet might do (e.g., camera toggle).
      // When Meet tries to set a video track, we substitute our canvas track.
      const origReplaceTrack = RTCRtpSender.prototype.replaceTrack;
      RTCRtpSender.prototype.replaceTrack = function(newTrack) {
        // IMPORTANT: Read from window.__vexa_canvas_stream (the GLOBAL), not the
        // closure variable. enableCamera() may create a fresh captureStream(30).
        const currentStream = window.__vexa_canvas_stream;
        if (newTrack && newTrack.kind === 'video' && currentStream) {
          const canvasTrack = currentStream.getVideoTracks()[0];
          // Only swap if the incoming track is NOT our canvas track
          if (canvasTrack && newTrack.id !== canvasTrack.id) {
            console.log('[Vexa] replaceTrack intercepted: substituting canvas track (blocked: ' + newTrack.label + ')');
            // CRITICAL: Don't just block — actually set our canvas track!
            // Returning Promise.resolve() would leave the sender with a null track.
            return origReplaceTrack.call(this, canvasTrack);
          }
        }
        return origReplaceTrack.call(this, newTrack);
      };

      // Ensure outbound video is present BEFORE offers are generated.
      // Teams guest/light meeting flow can create an offer with m=video inactive.
      // If no active video sender exists at offer-time, remote side never receives
      // a publishable camera track even if we replace tracks later.
      const origCreateOffer = OrigRTC.prototype.createOffer;
      OrigRTC.prototype.createOffer = async function(...offerArgs) {
        try {
          const currentStream = window.__vexa_canvas_stream;
          const canvasTrack = currentStream?.getVideoTracks?.()[0];
          if (canvasTrack) {
            const transceivers = this.getTransceivers ? this.getTransceivers() : [];
            let hasVideoSender = false;
            let attachedToExisting = false;

            for (const t of transceivers) {
              const receiverKind = t.receiver?.track?.kind;
              const senderKind = t.sender?.track?.kind;
              const isVideoTransceiver = receiverKind === 'video' || senderKind === 'video';
              if (!isVideoTransceiver) continue;

              // Force video-capable transceivers to allow sending.
              try {
                if (t.direction === 'inactive' || t.direction === 'recvonly') {
                  t.direction = 'sendrecv';
                }
              } catch {}

              if (t.sender?.track?.kind === 'video') {
                hasVideoSender = true;
                continue;
              }

              if (!t.sender?.track) {
                try {
                  await t.sender.replaceTrack(canvasTrack.clone());
                  attachedToExisting = true;
                  hasVideoSender = true;
                  console.log('[Vexa] createOffer pre-hook: attached canvas track to existing video transceiver (mid=' + (t.mid || 'null') + ')');
                } catch {}
              }
            }

            // If Teams did not keep a send-capable video transceiver, inject one.
            if (!hasVideoSender) {
              try {
                const tx = this.addTransceiver(canvasTrack.clone(), { direction: 'sendrecv' });
                window.__vexa_offer_video_forced = (window.__vexa_offer_video_forced || 0) + 1;
                console.log('[Vexa] createOffer pre-hook: added canvas video transceiver (mid=' + (tx?.mid || 'null') + ', attachedExisting=' + attachedToExisting + ')');
              } catch (addErr) {
                console.warn('[Vexa] createOffer pre-hook addTransceiver failed:', addErr);
              }
            }
          }
        } catch (offerHookErr) {
          console.warn('[Vexa] createOffer pre-hook failed:', offerHookErr);
        }
        return origCreateOffer.apply(this, offerArgs);
      };

      window.RTCPeerConnection = function(...args) {
        const pc = new OrigRTC(...args);
        window.__vexa_peer_connections.push(pc);
        console.log('[Vexa] New RTCPeerConnection created, total:', window.__vexa_peer_connections.length);
        pc.addEventListener('connectionstatechange', () => {
          if (pc.connectionState === 'closed' || pc.connectionState === 'failed') {
            const idx = window.__vexa_peer_connections.indexOf(pc);
            if (idx >= 0) window.__vexa_peer_connections.splice(idx, 1);
          }
        });
        return pc;
      };
      window.RTCPeerConnection.prototype = OrigRTC.prototype;
      // Copy static properties
      Object.keys(OrigRTC).forEach(key => {
        try { window.RTCPeerConnection[key] = OrigRTC[key]; } catch {}
      });

      // ===== 4. Patch enumerateDevices =====
      // Teams checks navigator.mediaDevices.enumerateDevices() to decide
      // whether to show the camera button. In a headless container there are
      // no physical cameras, so Teams disables the video toggle. We inject a
      // fake videoinput device so Teams enables the button. When Teams calls
      // getUserMedia, our patch above returns the canvas stream.
      const origEnumerateDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
      navigator.mediaDevices.enumerateDevices = async function() {
        const devices = await origEnumerateDevices();
        const hasVideo = devices.some(d => d.kind === 'videoinput');
        if (!hasVideo) {
          devices.push({
            deviceId: 'vexa-virtual-camera',
            kind: 'videoinput',
            label: 'Vexa Virtual Camera',
            groupId: 'vexa-virtual',
            toJSON() { return { deviceId: this.deviceId, kind: this.kind, label: this.label, groupId: this.groupId }; }
          });
          console.log('[Vexa] Injected virtual camera into enumerateDevices');
        }
        return devices;
      };

      console.log('[Vexa] getUserMedia + RTCPeerConnection + addTrack + createOffer + enumerateDevices patched for virtual camera');
      } catch (e) {
        console.error('[Vexa] Init script FAILED:', e);
      }
    })();
  `;
}
