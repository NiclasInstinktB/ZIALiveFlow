// Internationalisation setup.
//
// English is the fallback: an untranslated key shows English rather than a raw
// key, so a half-finished locale degrades gracefully instead of breaking the UI.
// The detected language is persisted in localStorage, so a reload keeps the
// choice without a round trip to the backend.
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "./locales/en.json";
import de from "./locales/de.json";
import fr from "./locales/fr.json";
import es from "./locales/es.json";
import it from "./locales/it.json";
import pt from "./locales/pt.json";
import nl from "./locales/nl.json";
import ja from "./locales/ja.json";
import zh from "./locales/zh.json";

// Each label is written in its own language, because someone who cannot read the
// current UI language still has to find their own entry in the list.
export const LANGUAGES = [
  { code: "en", label: "English" },
  { code: "de", label: "Deutsch" },
  { code: "fr", label: "Français" },
  { code: "es", label: "Español" },
  { code: "it", label: "Italiano" },
  { code: "pt", label: "Português" },
  { code: "nl", label: "Nederlands" },
  { code: "ja", label: "日本語" },
  { code: "zh", label: "简体中文" },
] as const;

export type LanguageCode = (typeof LANGUAGES)[number]["code"];

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      de: { translation: de },
      fr: { translation: fr },
      es: { translation: es },
      it: { translation: it },
      pt: { translation: pt },
      nl: { translation: nl },
      ja: { translation: ja },
      zh: { translation: zh },
    },
    fallbackLng: "en",
    supportedLngs: LANGUAGES.map((l) => l.code),
    // Regions collapse onto the base code: "de-AT" uses "de", "pt-BR" uses "pt",
    // "zh-Hans-CN" uses "zh". We do not ship regional variants.
    load: "languageOnly",
    interpolation: {
      // React escapes on render already; escaping here would double-encode.
      escapeValue: false,
    },
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: "lang",
      caches: ["localStorage"],
    },
  });

export default i18n;
