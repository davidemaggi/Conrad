import { useState } from "react";
import { Link } from "react-router";
import { Trans, useTranslation } from "react-i18next";
import { Download, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { CopyButton, ErrorAlert, LoadingRows, PageHeader } from "@/components/common";
import { Guide, type GuideEntry } from "@/components/Guide";
import { Logo } from "@/components/Logo";
import { useAuthorities } from "@/pages/Authorities";
import { colonHex } from "@/lib/utils";
import { useTitle } from "@/App";

function detect(): string {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua)) return "ios";
  if (/Android/.test(ua)) return "android";
  if (/Mac OS X/.test(ua)) return "macos";
  if (/Windows/.test(ua)) return "windows";
  if (/Firefox/.test(ua)) return "firefox";
  return "debian";
}

export default function InstallCA() {
  const { t } = useTranslation();
  useTitle(t("nav.install"));
  const q = useAuthorities();
  const [tab, setTab] = useState(detect);
  const root = q.data?.find((a) => a.kind === "root" && a.status === "active");
  const base = window.location.origin;
  const crt = `${base}/roots/current.crt`;
  const pem = `${base}/roots/current.pem`;
  const fp = root ? colonHex(root.fingerprintSha256) : "";
  const s = (id: string, n: number) => t(`install.${id}.s${n}`);

  const entries: GuideEntry[] = [
    {
      id: "windows", label: "Windows", hint: "PowerShell / certutil",
      steps: [
        { title: s("windows", 1), code: `curl.exe -fsSLk -o conrad-root-ca.crt ${crt}\ncertutil -hashfile conrad-root-ca.crt SHA256` },
        { title: s("windows", 2), code: `Import-Certificate -FilePath .\\conrad-root-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root` },
        { title: s("windows", 3), code: `certutil -addstore -f Root conrad-root-ca.crt` },
      ],
      note: t("install.windows.note"),
    },
    {
      id: "macos", label: "macOS", hint: "Keychain",
      steps: [
        { title: s("macos", 1), code: `curl -fsSLk -o conrad-root-ca.crt ${crt}\nopenssl x509 -inform der -in conrad-root-ca.crt -noout -fingerprint -sha256` },
        { title: s("macos", 2), code: `sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain conrad-root-ca.crt` },
      ],
      note: t("install.macos.note"),
    },
    {
      id: "debian", label: "Debian / Ubuntu", hint: "update-ca-certificates",
      steps: [
        { title: s("debian", 1), code: `sudo curl -fsSLk -o /usr/local/share/ca-certificates/conrad-root-ca.crt ${pem}\nopenssl x509 -in /usr/local/share/ca-certificates/conrad-root-ca.crt -noout -fingerprint -sha256` },
        { title: s("debian", 2), code: `sudo update-ca-certificates` },
      ],
    },
    {
      id: "fedora", label: "Fedora / RHEL", hint: "update-ca-trust",
      steps: [
        { title: s("fedora", 1), code: `sudo curl -fsSLk -o /etc/pki/ca-trust/source/anchors/conrad-root-ca.pem ${pem}` },
        { title: s("fedora", 2), code: `sudo update-ca-trust` },
      ],
    },
    {
      id: "arch", label: "Arch Linux", hint: "trust anchor",
      steps: [
        { title: s("arch", 1), code: `curl -fsSLk -o conrad-root-ca.pem ${pem}\nsudo trust anchor --store conrad-root-ca.pem` },
      ],
    },
    {
      id: "ios", label: "iOS / iPadOS",
      steps: [
        { title: <Trans i18nKey="install.ios.s1" components={{ a: <a className="font-medium text-primary underline" href={`${base}/roots/current.mobileconfig`} /> }} /> },
        { title: s("ios", 2) },
        { title: s("ios", 3) },
      ],
    },
    {
      id: "android", label: "Android",
      steps: [
        { title: <Trans i18nKey="install.android.s1" components={{ a: <a className="font-medium text-primary underline" href={crt} /> }} /> },
        { title: s("android", 2) },
      ],
      note: t("install.android.note"),
    },
    {
      id: "firefox", label: "Firefox", hint: "policies.json",
      steps: [
        { title: s("firefox", 1) },
        { title: s("firefox", 2), filename: "policies.json", code: `{\n  "policies": {\n    "Certificates": {\n      "ImportEnterpriseRoots": true,\n      "Install": ["/usr/local/share/ca-certificates/conrad-root-ca.crt"]\n    }\n  }\n}` },
      ],
    },
    {
      id: "docker", label: "Docker", hint: "Dockerfile",
      steps: [
        { title: s("docker", 1), code: `curl -fsSLk -o conrad-root-ca.crt ${pem}` },
        { title: s("docker", 2), filename: "Dockerfile", code: `# Debian / Ubuntu based images\nCOPY conrad-root-ca.crt /usr/local/share/ca-certificates/conrad-root-ca.crt\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \\\n && update-ca-certificates\n\n# Alpine\n# COPY conrad-root-ca.crt /usr/local/share/ca-certificates/\n# RUN apk add --no-cache ca-certificates && update-ca-certificates` },
      ],
    },
    {
      id: "runtimes", label: "Java · Node · Python", hint: t("install.runtimes.hint"),
      steps: [
        { title: s("runtimes", 1), code: `keytool -importcert -noprompt -cacerts -storepass changeit \\\n  -alias conrad-root-ca -file conrad-root-ca.crt` },
        { title: s("runtimes", 2), code: `export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/conrad-root-ca.crt` },
        { title: s("runtimes", 3), code: `export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nexport SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` },
      ],
    },
  ];

  return (
    <>
      <PageHeader eyebrow={t("nav.groups.guides")} title={t("nav.install")} description={t("install.description")} />
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-4" />
      <Card className="mb-6 overflow-hidden">
        <CardContent className="flex flex-col gap-5 p-5 sm:flex-row sm:items-center">
          <Logo size={72} className="shrink-0 anim-stamp" />
          {q.isPending ? <div className="flex-1"><LoadingRows rows={2} /></div> : root ? (
            <div className="min-w-0 flex-1">
              <p className="flex items-center gap-2 font-semibold"><ShieldCheck className="size-4 text-primary" aria-hidden /> {root.name}</p>
              <p className="mt-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("install.fingerprint")}</p>
              <div className="flex items-start gap-1">
                <code className="min-w-0 break-all font-mono text-xs leading-relaxed">{fp}</code>
                <CopyButton value={fp} />
              </div>
            </div>
          ) : (
            <p className="flex-1 text-sm text-muted-foreground">{t("install.noRoot")}</p>
          )}
          <div className="flex flex-wrap gap-2 sm:flex-col">
            <Button asChild><a href={crt} download><Download aria-hidden /> {t("install.downloadCrt")}</a></Button>
            <Button asChild variant="outline"><a href={pem} download><Download aria-hidden /> {t("install.downloadPem")}</a></Button>
          </div>
        </CardContent>
      </Card>
      <p className="mb-4 text-sm text-muted-foreground">{t("install.verifyHint")}</p>
      <Guide entries={entries} value={tab} onValueChange={setTab} label={t("install.platforms")} />
      <p className="mt-8 border-t pt-4 text-sm text-muted-foreground">
        {t("install.next")} <Link to="/clients" className="font-medium text-primary hover:underline">{t("nav.clients")} →</Link>
      </p>
    </>
  );
}
