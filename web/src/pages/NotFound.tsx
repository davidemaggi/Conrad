import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Logo } from "@/components/Logo";
import { useTitle } from "@/App";

export default function NotFound() {
  const { t } = useTranslation();
  useTitle(t("notFound.title"));
  return (
    <div className="mx-auto grid max-w-md place-items-center gap-4 py-20 text-center">
      <Logo size={112} className="-rotate-12 opacity-40 grayscale" />
      <h1 className="text-2xl font-semibold">{t("notFound.title")}</h1>
      <p className="text-muted-foreground">{t("notFound.text")}</p>
      <Button asChild><Link to="/">{t("notFound.home")}</Link></Button>
    </div>
  );
}
