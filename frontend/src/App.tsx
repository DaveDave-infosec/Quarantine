import { useEffect } from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import Marketing from "./pages/Marketing";
import ConsolePage from "./pages/Console";
import HowItWorks from "./pages/HowItWorks";
import Guide from "./pages/Guide";

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  return null;
}

export default function App() {
  return (
    <>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<Marketing />} />
        <Route path="/console" element={<ConsolePage />} />
        <Route path="/how-it-works" element={<HowItWorks />} />
        <Route path="/guide" element={<Guide />} />
        <Route path="*" element={<Marketing />} />
      </Routes>
    </>
  );
}
