"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "仪表盘" },
  { href: "/assets", label: "资产" },
  { href: "/findings", label: "发现" },
  { href: "/intercept", label: "审批" },
  { href: "/help", label: "帮助" },
];

export default function Nav() {
  const pathname = usePathname();
  return (
    <nav className="nav">
      <strong style={{ marginRight: 12 }}>PENTIGENT</strong>
      {links.map((l) => (
        <Link key={l.href} href={l.href} className={pathname === l.href ? "active" : ""}>
          {l.label}
        </Link>
      ))}
    </nav>
  );
}