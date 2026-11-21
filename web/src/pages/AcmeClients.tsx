import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { CopyButton, ErrorAlert, LoadingRows, PageHeader } from "@/components/common";
import { Guide, type GuideEntry } from "@/components/Guide";
import { useAuthorities } from "@/pages/Authorities";
import { useTitle } from "@/App";

export default function AcmeClients() {
  const { t } = useTranslation();
  useTitle(t("nav.clients"));
  const [params, setParams] = useSearchParams();
  const auths = useAuthorities();
  const issuers = (auths.data ?? []).filter((a) => a.kind === "intermediate" && a.status === "active");
  const slug = params.get("issuer") || issuers.find((i) => i.isDefault)?.slug || issuers[0]?.slug || "";
  const iss = issuers.find((i) => i.slug === slug);
  const root = auths.data?.find((a) => a.kind === "root" && a.status === "active");
  const pol = useQuery({ queryKey: ["policy", iss?.id], enabled: !!iss, queryFn: () => api.get<Policy>(`/authorities/${iss!.id}/policy`) });
  const suggested = (() => {
    const d = pol.data?.allowedDomains?.find((x) => x.startsWith("*.") || !x.includes("*"));
    return d ? `myhost.${d.replace(/^\*\./, "")}` : "myhost.home.lab";
  })();
  const [hostInput, setHost] = useState("");
  const host = hostInput.trim() || suggested;
  const [tab, setTab] = useState("certbot");
  const dir = iss?.directoryUrl ?? "";
  const eab = !!pol.data?.requireEAB;
  const K = "<EAB_KID>", H = "<EAB_HMAC>";
  const rootPem = "/usr/local/share/ca-certificates/conrad-root-ca.crt";
  const caBundle = root ? btoa(root.certPem) : "<base64 root PEM>";
  const n = (id: string, k: number) => t(`clients.${id}.s${k}`);

  const entries: GuideEntry[] = [
    {
      id: "certbot", label: "Certbot", hint: "Linux · nginx · Apache",
      steps: [
        { title: n("certbot", 1), code: `sudo REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\\n  certbot certonly --standalone \\\n  --server ${dir} \\\n${eab ? `  --eab-kid ${K} --eab-hmac-key ${H} \\\n` : ""}  --agree-tos --register-unsafely-without-email \\\n  -d ${host}` },
        { title: n("certbot", 2), code: `sudo REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\\n  certbot --nginx --server ${dir} -d ${host}` },
        { title: n("certbot", 3), code: `sudo certbot renew --dry-run` },
      ],
      note: t("clients.certbot.note"),
    },
    {
      id: "acmesh", label: "acme.sh", hint: "shell",
      steps: [
        ...(eab ? [{ title: n("acmesh", 0), code: `acme.sh --register-account --server ${dir} \\\n  --ca-bundle ${rootPem} \\\n  --eab-kid ${K} --eab-hmac-key ${H}` }] : []),
        { title: n("acmesh", 1), code: `acme.sh --issue --server ${dir} \\\n  --ca-bundle ${rootPem} \\\n  --standalone -d ${host}` },
        { title: n("acmesh", 2), code: `acme.sh --install-cert -d ${host} \\\n  --key-file /etc/ssl/private/${host}.key \\\n  --fullchain-file /etc/ssl/certs/${host}.pem \\\n  --reloadcmd "systemctl reload nginx"` },
      ],
    },
    {
      id: "lego", label: "lego", hint: "Go CLI",
      steps: [
        { title: n("lego", 1), code: `LEGO_CA_CERTIFICATES=${rootPem} lego \\\n  --server ${dir} \\\n${eab ? `  --eab --kid ${K} --hmac ${H} \\\n` : ""}  --accept-tos --email admin@${host.split(".").slice(1).join(".") || "home.lab"} \\\n  --domains ${host} --http run` },
      ],
    },
    {
      id: "caddy", label: "Caddy", hint: "Caddyfile",
      steps: [
        { title: n("caddy", 1) },
        { title: n("caddy", 2), filename: "Caddyfile", code: `{\n\tacme_ca ${dir}\n\tacme_ca_root /etc/caddy/conrad-root-ca.crt\n${eab ? `\tacme_eab {\n\t\tkey_id ${K}\n\t\tmac_key ${H}\n\t}\n` : ""}}\n\n${host} {\n\treverse_proxy localhost:8080\n}` },
      ],
    },
    {
      id: "traefik", label: "Traefik", hint: "traefik.yml",
      steps: [
        { title: n("traefik", 1), filename: "traefik.yml", code: `certificatesResolvers:\n  conrad:\n    acme:\n      caServer: ${dir}\n      email: admin@home.lab\n      storage: /letsencrypt/acme.json\n      httpChallenge:\n        entryPoint: web\n${eab ? `      eab:\n        kid: ${K}\n        hmacEncoded: ${H}\n` : ""}` },
        { title: n("traefik", 2), filename: "compose.yaml", code: `services:\n  traefik:\n    environment:\n      LEGO_CA_CERTIFICATES: /certs/conrad-root-ca.crt\n    volumes:\n      - ./conrad-root-ca.crt:/certs/conrad-root-ca.crt:ro\n    labels:\n      - traefik.http.routers.app.tls.certresolver=conrad` },
      ],
    },
    {
      id: "certmanager", label: "cert-manager", hint: "Kubernetes",
      steps: [
        ...(eab ? [{ title: n("certmanager", 0), code: `kubectl -n cert-manager create secret generic conrad-eab \\\n  --from-literal=secret=${H}` }] : []),
        { title: n("certmanager", 1), filename: "clusterissuer.yaml", code: `apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata:\n  name: conrad-${slug}\nspec:\n  acme:\n    server: ${dir}\n    caBundle: ${caBundle}\n    privateKeySecretRef:\n      name: conrad-${slug}-account\n${eab ? `    externalAccountBinding:\n      keyID: ${K}\n      keySecretRef:\n        name: conrad-eab\n        key: secret\n` : ""}    solvers:\n      - http01:\n          ingress:\n            ingressClassName: nginx` },
        { title: n("certmanager", 2), code: `metadata:\n  annotations:\n    cert-manager.io/cluster-issuer: conrad-${slug}` },
      ],
    },
    {
      id: "winacme", label: "win-acme", hint: "Windows · IIS",
      steps: [
        { title: n("winacme", 1), code: `wacs.exe --baseuri ${dir} \\\n  --source manual --host ${host} \\\n${eab ? `  --eab-key-identifier ${K} --eab-key ${H} \\\n` : ""}  --accepttos`.replace(/ \\\n/g, " `\n") },
      ],
    },
  ];

  return (
    <>
      <PageHeader eyebrow={t("nav.groups.guides")} title={t("nav.clients")} description={t("clients.description")} />
      <ErrorAlert error={auths.error ?? pol.error} className="mb-4" />
      <Card className="mb-6">
        <CardContent className="grid gap-4 p-5 md:grid-cols-[14rem_14rem_1fr] md:items-end">
          <Field label={t("certs.issuer")}>
            <Select value={slug} onValueChange={(v) => setParams({ issuer: v }, { replace: true })} options={issuers.map((i) => ({ value: i.slug, label: `${i.name} (${i.slug})` }))} />
          </Field>
          <Field label={t("clients.hostname")}>
            <Input value={hostInput} onChange={(e) => setHost(e.target.value)} placeholder={suggested} className="font-mono" />
          </Field>
          <div className="min-w-0">
            <p className="mb-1.5 text-sm font-medium">{t("authorities.directory")}</p>
            <div className="flex items-center gap-1 rounded-md border bg-muted/40 py-1 pl-3 pr-1">
              <code className="min-w-0 flex-1 truncate font-mono text-[13px]" title={dir}>{dir || "—"}</code>
              {dir && <CopyButton value={dir} />}
            </div>
          </div>
        </CardContent>
        {eab && iss && (
          <p className="flex flex-wrap items-center gap-2 border-t px-5 py-3 text-sm">
            <Badge variant="warning"><KeyRound className="size-3" aria-hidden /> EAB</Badge>
            {t("clients.eabRequired")}
            <Link to={`/authorities/${iss.id}`} className="font-medium text-primary hover:underline">{t("clients.eabCreate")}</Link>
          </p>
        )}
      </Card>
      <p className="mb-4 text-sm text-muted-foreground">
        {t("clients.trustFirst")} <Link to="/install" className="font-medium text-primary hover:underline">{t("nav.install")}</Link>
      </p>
      {auths.isPending ? <LoadingRows /> : <Guide entries={entries} value={tab} onValueChange={setTab} label={t("clients.clients")} />}
    </>
  );
}
