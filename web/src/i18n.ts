import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import en from "./locales/en.json";
import it from "./locales/it.json";

export const LANGUAGES = [
  { code: "en", label: "English" },
  { code: "it", label: "Italiano" },
] as const;

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { en: { translation: en }, it: { translation: it } },
    fallbackLng: "en",
    supportedLngs: ["en", "it"],
    nonExplicitSupportedLngs: true,
    interpolation: { escapeValue: false },
    detection: { order: ["localStorage", "navigator"], caches: ["localStorage"] },
    returnNull: false,
  });

i18n.on("languageChanged", (l) => {
  document.documentElement.lang = l.slice(0, 2);
});

export default i18n;
