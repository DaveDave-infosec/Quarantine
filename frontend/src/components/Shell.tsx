import type { ReactNode } from "react";
import Nav from "./Nav";
import Footer from "./Footer";

export default function Shell({
  children,
  variant = "marketing",
}: {
  children: ReactNode;
  variant?: "marketing" | "app";
}) {
  return (
    <div className="shell">
      <Nav variant={variant} />
      <main className="shell-main">{children}</main>
      <Footer />
    </div>
  );
}
