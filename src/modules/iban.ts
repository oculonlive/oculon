/**
 * IBAN check, fully offline: country, length, the ISO 13616 mod-97 check digits, the bank part of the number
 * and, for an invoice, whether the account country matches the supplier's country.
 * A valid IBAN only proves the number is well formed. It cannot tell who owns the account.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult } from '../core/types.js';

/** IBAN length per country (SWIFT IBAN registry). */
const LENGTHS: Record<string, [number, string]> = {
  AD: [24, 'Andorra'], AE: [23, 'United Arab Emirates'], AL: [28, 'Albania'], AT: [20, 'Austria'], AZ: [28, 'Azerbaijan'], BA: [20, 'Bosnia and Herzegovina'],
  BE: [16, 'Belgium'], BG: [22, 'Bulgaria'], BH: [22, 'Bahrain'], BR: [29, 'Brazil'], BY: [28, 'Belarus'], CH: [21, 'Switzerland'], CR: [22, 'Costa Rica'],
  CY: [28, 'Cyprus'], CZ: [24, 'Czechia'], DE: [22, 'Germany'], DK: [18, 'Denmark'], DO: [28, 'Dominican Republic'], EE: [20, 'Estonia'], EG: [29, 'Egypt'],
  ES: [24, 'Spain'], FI: [18, 'Finland'], FO: [18, 'Faroe Islands'], FR: [27, 'France'], GB: [22, 'United Kingdom'], GE: [22, 'Georgia'], GI: [23, 'Gibraltar'],
  GL: [18, 'Greenland'], GR: [27, 'Greece'], GT: [28, 'Guatemala'], HR: [21, 'Croatia'], HU: [28, 'Hungary'], IE: [22, 'Ireland'], IL: [23, 'Israel'],
  IQ: [23, 'Iraq'], IS: [26, 'Iceland'], IT: [27, 'Italy'], JO: [30, 'Jordan'], KW: [30, 'Kuwait'], KZ: [20, 'Kazakhstan'], LB: [28, 'Lebanon'],
  LC: [32, 'Saint Lucia'], LI: [21, 'Liechtenstein'], LT: [20, 'Lithuania'], LU: [20, 'Luxembourg'], LV: [21, 'Latvia'], LY: [25, 'Libya'], MC: [27, 'Monaco'],
  MD: [24, 'Moldova'], ME: [22, 'Montenegro'], MK: [19, 'North Macedonia'], MR: [27, 'Mauritania'], MT: [31, 'Malta'], MU: [30, 'Mauritius'], NL: [18, 'Netherlands'],
  NO: [15, 'Norway'], PK: [24, 'Pakistan'], PL: [28, 'Poland'], PS: [29, 'Palestine'], PT: [25, 'Portugal'], QA: [29, 'Qatar'], RO: [24, 'Romania'],
  RS: [22, 'Serbia'], RU: [33, 'Russia'], SA: [24, 'Saudi Arabia'], SC: [31, 'Seychelles'], SD: [18, 'Sudan'], SE: [24, 'Sweden'], SI: [19, 'Slovenia'],
  SK: [24, 'Slovakia'], SM: [27, 'San Marino'], ST: [25, 'Sao Tome and Principe'], SV: [28, 'El Salvador'], TL: [23, 'Timor-Leste'], TN: [24, 'Tunisia'],
  TR: [26, 'Turkey'], UA: [29, 'Ukraine'], VA: [22, 'Vatican City'], VG: [24, 'British Virgin Islands'], XK: [20, 'Kosovo'],
};

/** Where the bank identifier sits in the BBAN (start, length), for countries where it is well defined. */
const BANK: Record<string, [number, number, string]> = {
  DE: [0, 8, 'Bankleitzahl'], AT: [0, 5, 'bank code'], CH: [0, 5, 'clearing number'], NL: [0, 4, 'bank code'], BE: [0, 3, 'bank code'], FR: [0, 5, 'bank code'],
  ES: [0, 4, 'bank code'], IT: [1, 5, 'ABI code'], GB: [0, 4, 'bank code'], IE: [0, 4, 'bank code'], PL: [0, 8, 'bank and branch code'], SE: [0, 3, 'bank code'],
  DK: [0, 4, 'bank code'], FI: [0, 3, 'bank code'], NO: [0, 4, 'bank code'], PT: [0, 4, 'bank code'], LU: [0, 3, 'bank code'], CZ: [0, 4, 'bank code'],
};

export interface IbanCheck {
  input: string;
  iban: string | null;
  formatted: string | null;
  valid: boolean;
  country: string | null;
  countryName: string | null;
  checkDigits: string | null;
  bank: { code: string; kind: string } | null;
  sortCode: string | null;
  problems: string[];
  warnings: string[];
  advice: string[];
}

/** ISO 7064 mod 97-10 over the rearranged IBAN, with letters as 10..35. */
export function mod97(iban: string): number {
  const s = (iban.slice(4) + iban.slice(0, 4)).toUpperCase().replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let r = 0;
  for (let i = 0; i < s.length; i += 7) r = Number(String(r) + s.slice(i, i + 7)) % 97;
  return r;
}

export function checkIban(input: string, supplierCountry?: string): IbanCheck {
  const iban = input.replace(/^iban[:\s]*/i, '').replace(/[\s-]/g, '').toUpperCase();
  const problems: string[] = [], warnings: string[] = [];
  const out: IbanCheck = { input, iban: iban || null, formatted: null, valid: false, country: null, countryName: null, checkDigits: null, bank: null, sortCode: null, problems, warnings, advice: [] };
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{8,30}$/.test(iban)) {
    problems.push('not an IBAN: it should start with a two-letter country code and two check digits, followed by the account number');
  } else {
    const cc = iban.slice(0, 2);
    out.country = cc; out.checkDigits = iban.slice(2, 4); out.formatted = iban.replace(/(.{4})/g, '$1 ').trim();
    const spec = LENGTHS[cc];
    if (!spec) problems.push(`${cc} does not issue IBANs`);
    else {
      out.countryName = spec[1];
      if (iban.length !== spec[0]) problems.push(`${spec[1]} IBANs have ${spec[0]} characters, this one has ${iban.length}`);
    }
    if (mod97(iban) !== 1) problems.push('the check digits do not match: a character is wrong or missing');
    const b = BANK[cc];
    if (b && !problems.length) out.bank = { code: iban.slice(4 + b[0], 4 + b[0] + b[1]), kind: b[2] };
    if (cc === 'GB' && !problems.length) out.sortCode = iban.slice(8, 14).replace(/(\d\d)(\d\d)(\d\d)/, '$1-$2-$3');
    out.valid = problems.length === 0;
  }
  const sc = supplierCountry?.trim().toUpperCase();
  if (out.valid && sc && /^[A-Z]{2}$/.test(sc) && sc !== out.country) {
    warnings.push(`the account is in ${out.countryName ?? out.country}, but the supplier is in ${LENGTHS[sc]?.[1] ?? sc}: a common sign of invoice fraud`);
  }
  out.advice = out.valid
    ? ['A valid IBAN only means the number is well formed. Before paying new bank details, call the supplier on a number you already have, not one from the email.']
    : ['Do not pay to this number. Ask the supplier to confirm their bank details through a channel you already trust.'];
  if (warnings.length) out.advice.unshift('Treat a change of bank country as a red flag until the supplier confirms it by phone.');
  return out;
}

export async function ibanCheck(ctx: Ctx, input: string, opts: { country?: string } = {}): Promise<ModuleResult<IbanCheck>> {
  if (!input?.trim()) throw new Error('give an IBAN, for example DE89 3704 0044 0532 0130 00');
  const r = checkIban(input.trim(), opts.country);
  return {
    module: 'iban',
    input: r.formatted ?? input.trim(),
    generatedAt: ctx.now().toISOString(),
    result: r,
    signals: [],
    provenance: [{ source: 'iban-registry', url: 'https://www.swift.com/standards/data-standards/iban-international-bank-account-number', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: 'offline check: ISO 13616 lengths and mod-97 check digits' }],
  };
}
