import { lazy, Suspense, useEffect, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";
import { useMe, useStatus, useUnauthorizedListener } from "@/lib/session";
import { AppShell } from "@/components/AppShell";
import { ErrorAlert } from "@/components/common";
import { Logo } from "@/components/Logo";

const Setup = lazy(() => import("@/pages/Setup"));
const Login = lazy(() => import("@/pages/Login"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Authorities = lazy(() => import("@/pages/Authorities"));
const AuthorityDetail = lazy(() => import("@/pages/AuthorityDetail"));
const Certificates = lazy(() => import("@/pages/Certificates"));
const CertificateDetail = lazy(() => import("@/pages/CertificateDetail"));
const Accounts = lazy(() => import("@/pages/Accounts"));
const InstallCA = lazy(() => import("@/pages/InstallCA"));
const AcmeClients = lazy(() => import("@/pages/AcmeClients"));
const Notifications = lazy(() => import("@/pages/Notifications"));
const Audit = lazy(() => import("@/pages/Audit"));
const Settings = lazy(() => import("@/pages/Settings"));
const NotFound = lazy(() => import("@/pages/NotFound"));

function Splash() {
  return (
    <div className="flex min-h-dvh items-center justify-center" aria-busy="true">
      <Logo size={64} className="animate-pulse" />
    </div>
  );
}

function PageFallback() {
  return <div className="h-40" aria-busy="true" />;
}

/** Sets the document title and moves focus to <main> on navigation (screen readers). */
function RouteEffects() {
  const loc = useLocation();
  useEffect(() => {
    const main = document.getElementById("main");
    if (main && document.activeElement !== main && loc.pathname !== "/login") main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [loc.pathname]);
  return null;
}

export function useTitle(title: string) {
  useEffect(() => {
    document.title = title ? `${title} · Conrad` : "Conrad";
  }, [title]);
}

export default function App() {
  useUnauthorizedListener();
  const status = useStatus();
  const authed = !!status.data?.authenticated && !status.data?.setupRequired;
  const me = useMe(authed);

  if (status.isPending) return <Splash />;
  if (status.isError)
    return (
      <div className="mx-auto mt-24 max-w-md p-6">
        <ErrorAlert error={status.error} onRetry={() => void status.refetch()} />
      </div>
    );
  const s = status.data;

  let content: ReactNode;
  if (s.setupRequired) {
    content = (
      <Routes>
        <Route path="/setup" element={<Setup status={s} />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    );
  } else if (!s.authenticated) {
    content = (
      <Routes>
        <Route path="/login" element={<Login status={s} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  } else if (me.isPending) {
    content = <Splash />;
  } else if (me.isError) {
    content = (
      <div className="mx-auto mt-24 max-w-md p-6">
        <ErrorAlert error={me.error} onRetry={() => void me.refetch()} />
      </div>
    );
  } else {
    content = (
      <AppShell me={me.data} status={s}>
        <RouteEffects />
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/authorities" element={<Authorities />} />
            <Route path="/authorities/:id" element={<AuthorityDetail />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/certificates/:id" element={<CertificateDetail />} />
            <Route path="/accounts" element={<Accounts />} />
            <Route path="/install" element={<InstallCA />} />
            <Route path="/clients" element={<AcmeClients />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings me={me.data} />} />
            <Route path="/login" element={<Navigate to="/" replace />} />
            <Route path="/setup" element={<Navigate to="/" replace />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </AppShell>
    );
  }
  return <Suspense fallback={<Splash />}>{content}</Suspense>;
}
