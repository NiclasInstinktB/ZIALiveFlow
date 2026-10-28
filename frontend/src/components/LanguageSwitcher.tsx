import { useTranslation } from "react-i18next";
import { LANGUAGES } from "../i18n";

// Plain <select> rather than a custom dropdown: it is keyboard accessible and
// renders natively on mobile without any extra work.
export function LanguageSwitcher() {
  const { i18n, t } = useTranslation();
  // i18n.language may carry a region ("de-DE"); the options are plain codes.
  const current = i18n.resolvedLanguage ?? i18n.language.split("-")[0];

  return (
    <select
      className="lang-select"
      value={current}
      aria-label={t("common.language")}
      title={t("common.language")}
      onChange={(e) => void i18n.changeLanguage(e.target.value)}
    >
      {LANGUAGES.map((l) => (
        <option key={l.code} value={l.code}>
          {l.label}
        </option>
      ))}
    </select>
  );
}
