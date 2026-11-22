export const API_BASE_URL = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

export function getWsUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  if (import.meta.env.VITE_WS_URL) {
    const base = import.meta.env.VITE_WS_URL.replace(/\/$/, "");
    return `${base}${normalizedPath}`;
  }
  
  const apiBase =
    import.meta.env.VITE_API_URL ||
    (typeof window !== "undefined" && window.location.hostname.includes("vercel.app")
      ? "https://phishguard-hqku.onrender.com"
      : "");

  if (apiBase) {
    try {
      const url = new URL(apiBase);
      const wsProto = url.protocol === "https:" ? "wss:" : "ws:";
      return `${wsProto}//${url.host}${normalizedPath}`;
    } catch {
      // fallback
    }
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}${normalizedPath}`;
}
