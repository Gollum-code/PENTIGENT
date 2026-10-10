"use client";
import { useToast } from "@/lib/store";

export default function Toast() {
  const { msg, type } = useToast();
  if (!msg) return null;
  const color = type === "ok" ? "#3fb950" : "#ff7b72";
  return (
    <div
      style={{
        position: "fixed",
        bottom: 24,
        left: "50%",
        transform: "translateX(-50%)",
        background: "#161b22",
        border: `1px solid ${color}`,
        color: color,
        padding: "10px 18px",
        borderRadius: 8,
        zIndex: 999,
        boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
        maxWidth: "80%",
      }}
    >
      {msg}
    </div>
  );
}