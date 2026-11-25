/**
 * Phone number check, for the sender of a suspicious SMS or a missed call from abroad.
 * Offline: country from the calling code, number length, premium-rate and "one ring" callback-scam codes.
 * Online (NUMVERIFY_API_KEY, free 100 lookups a month): validity, carrier, line type (mobile, landline, VoIP)
 * and location. Owner names are never looked up.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface PhoneCheck {
  e164: string;
  countryCode: string;
  country: string | null;
  iso2: string | null;
  plausible: boolean;
  lineType: string | null;
  carrier: string | null;
  location: string | null;
  valid: boolean | null;
  risk: 'high' | 'medium' | 'low';
  warnings: string[];
  advice: string[];
}

/** ITU calling codes → [ISO 3166 code, country]. +1 and +7 are shared plans and named as such. */
const CODES: Record<string, [string, string]> = {
  '1': ['', 'United States, Canada or the Caribbean (North American plan)'], '7': ['', 'Russia or Kazakhstan'],
  '20': ['EG', 'Egypt'], '27': ['ZA', 'South Africa'], '30': ['GR', 'Greece'], '31': ['NL', 'Netherlands'], '32': ['BE', 'Belgium'], '33': ['FR', 'France'], '34': ['ES', 'Spain'], '36': ['HU', 'Hungary'], '39': ['IT', 'Italy'],
  '40': ['RO', 'Romania'], '41': ['CH', 'Switzerland'], '43': ['AT', 'Austria'], '44': ['GB', 'United Kingdom'], '45': ['DK', 'Denmark'], '46': ['SE', 'Sweden'], '47': ['NO', 'Norway'], '48': ['PL', 'Poland'], '49': ['DE', 'Germany'],
  '51': ['PE', 'Peru'], '52': ['MX', 'Mexico'], '53': ['CU', 'Cuba'], '54': ['AR', 'Argentina'], '55': ['BR', 'Brazil'], '56': ['CL', 'Chile'], '57': ['CO', 'Colombia'], '58': ['VE', 'Venezuela'],
  '60': ['MY', 'Malaysia'], '61': ['AU', 'Australia'], '62': ['ID', 'Indonesia'], '63': ['PH', 'Philippines'], '64': ['NZ', 'New Zealand'], '65': ['SG', 'Singapore'], '66': ['TH', 'Thailand'],
  '81': ['JP', 'Japan'], '82': ['KR', 'South Korea'], '84': ['VN', 'Vietnam'], '86': ['CN', 'China'], '90': ['TR', 'Turkey'], '91': ['IN', 'India'], '92': ['PK', 'Pakistan'], '93': ['AF', 'Afghanistan'], '94': ['LK', 'Sri Lanka'], '95': ['MM', 'Myanmar'], '98': ['IR', 'Iran'],
  '211': ['SS', 'South Sudan'], '212': ['MA', 'Morocco'], '213': ['DZ', 'Algeria'], '216': ['TN', 'Tunisia'], '218': ['LY', 'Libya'], '220': ['GM', 'Gambia'], '221': ['SN', 'Senegal'], '222': ['MR', 'Mauritania'], '223': ['ML', 'Mali'], '224': ['GN', 'Guinea'], '225': ['CI', "Côte d'Ivoire"], '226': ['BF', 'Burkina Faso'], '227': ['NE', 'Niger'], '228': ['TG', 'Togo'], '229': ['BJ', 'Benin'],
  '230': ['MU', 'Mauritius'], '231': ['LR', 'Liberia'], '232': ['SL', 'Sierra Leone'], '233': ['GH', 'Ghana'], '234': ['NG', 'Nigeria'], '235': ['TD', 'Chad'], '236': ['CF', 'Central African Republic'], '237': ['CM', 'Cameroon'], '238': ['CV', 'Cape Verde'], '239': ['ST', 'São Tomé and Príncipe'],
  '240': ['GQ', 'Equatorial Guinea'], '241': ['GA', 'Gabon'], '242': ['CG', 'Congo'], '243': ['CD', 'DR Congo'], '244': ['AO', 'Angola'], '245': ['GW', 'Guinea-Bissau'], '248': ['SC', 'Seychelles'], '249': ['SD', 'Sudan'], '250': ['RW', 'Rwanda'], '251': ['ET', 'Ethiopia'], '252': ['SO', 'Somalia'], '253': ['DJ', 'Djibouti'], '254': ['KE', 'Kenya'], '255': ['TZ', 'Tanzania'], '256': ['UG', 'Uganda'], '257': ['BI', 'Burundi'], '258': ['MZ', 'Mozambique'],
  '260': ['ZM', 'Zambia'], '261': ['MG', 'Madagascar'], '262': ['RE', 'Réunion or Mayotte'], '263': ['ZW', 'Zimbabwe'], '264': ['NA', 'Namibia'], '265': ['MW', 'Malawi'], '266': ['LS', 'Lesotho'], '267': ['BW', 'Botswana'], '268': ['SZ', 'Eswatini'], '269': ['KM', 'Comoros'],
  '290': ['SH', 'Saint Helena'], '291': ['ER', 'Eritrea'], '297': ['AW', 'Aruba'], '298': ['FO', 'Faroe Islands'], '299': ['GL', 'Greenland'],
  '350': ['GI', 'Gibraltar'], '351': ['PT', 'Portugal'], '352': ['LU', 'Luxembourg'], '353': ['IE', 'Ireland'], '354': ['IS', 'Iceland'], '355': ['AL', 'Albania'], '356': ['MT', 'Malta'], '357': ['CY', 'Cyprus'], '358': ['FI', 'Finland'], '359': ['BG', 'Bulgaria'],
  '370': ['LT', 'Lithuania'], '371': ['LV', 'Latvia'], '372': ['EE', 'Estonia'], '373': ['MD', 'Moldova'], '374': ['AM', 'Armenia'], '375': ['BY', 'Belarus'], '376': ['AD', 'Andorra'], '377': ['MC', 'Monaco'], '378': ['SM', 'San Marino'], '380': ['UA', 'Ukraine'], '381': ['RS', 'Serbia'], '382': ['ME', 'Montenegro'], '383': ['XK', 'Kosovo'], '385': ['HR', 'Croatia'], '386': ['SI', 'Slovenia'], '387': ['BA', 'Bosnia and Herzegovina'], '389': ['MK', 'North Macedonia'],
  '420': ['CZ', 'Czechia'], '421': ['SK', 'Slovakia'], '423': ['LI', 'Liechtenstein'],
  '500': ['FK', 'Falkland Islands'], '501': ['BZ', 'Belize'], '502': ['GT', 'Guatemala'], '503': ['SV', 'El Salvador'], '504': ['HN', 'Honduras'], '505': ['NI', 'Nicaragua'], '506': ['CR', 'Costa Rica'], '507': ['PA', 'Panama'], '509': ['HT', 'Haiti'], '590': ['GP', 'Guadeloupe'], '591': ['BO', 'Bolivia'], '592': ['GY', 'Guyana'], '593': ['EC', 'Ecuador'], '595': ['PY', 'Paraguay'], '597': ['SR', 'Suriname'], '598': ['UY', 'Uruguay'], '599': ['CW', 'Curaçao or Caribbean Netherlands'],
  '670': ['TL', 'Timor-Leste'], '673': ['BN', 'Brunei'], '674': ['NR', 'Nauru'], '675': ['PG', 'Papua New Guinea'], '676': ['TO', 'Tonga'], '677': ['SB', 'Solomon Islands'], '678': ['VU', 'Vanuatu'], '679': ['FJ', 'Fiji'], '680': ['PW', 'Palau'], '682': ['CK', 'Cook Islands'], '685': ['WS', 'Samoa'], '686': ['KI', 'Kiribati'], '687': ['NC', 'New Caledonia'], '688': ['TV', 'Tuvalu'], '689': ['PF', 'French Polynesia'], '691': ['FM', 'Micronesia'], '692': ['MH', 'Marshall Islands'],
  '850': ['KP', 'North Korea'], '852': ['HK', 'Hong Kong'], '853': ['MO', 'Macau'], '855': ['KH', 'Cambodia'], '856': ['LA', 'Laos'], '880': ['BD', 'Bangladesh'], '886': ['TW', 'Taiwan'],
  '960': ['MV', 'Maldives'], '961': ['LB', 'Lebanon'], '962': ['JO', 'Jordan'], '963': ['SY', 'Syria'], '964': ['IQ', 'Iraq'], '965': ['KW', 'Kuwait'], '966': ['SA', 'Saudi Arabia'], '967': ['YE', 'Yemen'], '968': ['OM', 'Oman'], '970': ['PS', 'Palestine'], '971': ['AE', 'United Arab Emirates'], '972': ['IL', 'Israel'], '973': ['BH', 'Bahrain'], '974': ['QA', 'Qatar'], '975': ['BT', 'Bhutan'], '976': ['MN', 'Mongolia'], '977': ['NP', 'Nepal'],
  '992': ['TJ', 'Tajikistan'], '993': ['TM', 'Turkmenistan'], '994': ['AZ', 'Azerbaijan'], '995': ['GE', 'Georgia'], '996': ['KG', 'Kyrgyzstan'], '998': ['UZ', 'Uzbekistan'],
  '882': ['', 'International networks (satellite or global)'], '883': ['', 'International networks (global)'], '881': ['', 'Satellite phone (global mobile satellite system)'], '870': ['', 'Inmarsat satellite phone'], '979': ['', 'International premium-rate service'], '808': ['', 'International shared-cost service'], '800': ['', 'International freephone'],
};

/** North American area codes in other countries that the FCC warns about in "one ring" callback scams. */
const ONE_RING: Record<string, string> = { '268': 'Antigua and Barbuda', '284': 'British Virgin Islands', '473': 'Grenada', '649': 'Turks and Caicos', '664': 'Montserrat', '767': 'Dominica', '809': 'Dominican Republic', '829': 'Dominican Republic', '849': 'Dominican Republic', '876': 'Jamaica' };
/** Other North American area codes outside the US and Canada (calls are charged as international). */
const NANP_OTHER: Record<string, string> = { '242': 'Bahamas', '246': 'Barbados', '264': 'Anguilla', '340': 'US Virgin Islands', '345': 'Cayman Islands', '441': 'Bermuda', '658': 'Jamaica', '671': 'Guam', '670': 'Northern Mariana Islands', '684': 'American Samoa', '721': 'Sint Maarten', '758': 'Saint Lucia', '784': 'Saint Vincent and the Grenadines', '787': 'Puerto Rico', '939': 'Puerto Rico', '868': 'Trinidad and Tobago', '869': 'Saint Kitts and Nevis' };

const ISO_TO_CODE: Record<string, string> = Object.fromEntries(Object.entries(CODES).filter(([, v]) => v[0]).map(([k, v]) => [v[0], k]));
Object.assign(ISO_TO_CODE, { US: '1', CA: '1', KZ: '7', RU: '7' });

/** Normalise to E.164 digits. A national number needs a default country (ISO code). */
export function toE164(input: string, defaultCountry?: string): { digits: string; code: string } | null {
  let s = input.trim().replace(/[\s().\-/]/g, '');
  if (s.startsWith('00')) s = `+${s.slice(2)}`;
  if (!/^\+?\d{6,16}$/.test(s)) return null;
  if (!s.startsWith('+')) {
    const cc = defaultCountry ? ISO_TO_CODE[defaultCountry.toUpperCase()] : undefined;
    if (!cc) return null;
    s = `+${cc}${s.replace(/^0+/, '')}`;
  }
  const digits = s.slice(1);
  for (const len of [3, 2, 1]) {
    const code = digits.slice(0, len);
    if (CODES[code]) return { digits, code };
  }
  return null;
}

/** What can be told without any lookup. */
export function offlinePhone(digits: string, code: string): Pick<PhoneCheck, 'country' | 'iso2' | 'plausible' | 'lineType' | 'warnings'> {
  const [iso2, country] = CODES[code]!;
  const national = digits.slice(code.length);
  const warnings: string[] = [];
  let lineType: string | null = null;
  let iso: string | null = iso2 || null;
  let name: string | null = country;
  let plausible = digits.length >= 8 && digits.length <= 15;
  if (code === '1') {
    plausible = national.length === 10 && /^[2-9]\d{2}[2-9]/.test(national);
    const area = national.slice(0, 3);
    if (ONE_RING[area]) { iso = null; name = ONE_RING[area]!; warnings.push(`Area code ${area} is ${ONE_RING[area]}: it looks like a US number but calls are charged as international. The FCC warns about "one ring" scams from this code; do not call back.`); }
    else if (NANP_OTHER[area]) { name = NANP_OTHER[area]!; iso = null; }
    if (/^(900|976)/.test(national)) { lineType = 'premium rate'; warnings.push('900 and 976 numbers are premium rate: calling costs money per minute.'); }
    if (/^8(00|33|44|55|66|77|88)/.test(national)) lineType = 'toll free';
  }
  if (code === '44') {
    if (/^9/.test(national)) { lineType = 'premium rate'; warnings.push('UK 09 numbers are premium rate: calls can cost several pounds a minute.'); }
    if (/^70/.test(national)) { lineType = 'personal number'; warnings.push('UK 070 "personal numbers" look like mobiles but are expensive to call and are often used by scammers.'); }
    if (/^7[1-9]/.test(national)) lineType = 'mobile';
  }
  if (code === '979') warnings.push('+979 is an international premium-rate code: calling it costs money.');
  if (['881', '882', '883', '870'].includes(code)) warnings.push('Satellite and international network numbers are very expensive to call; a stranger has little reason to use one.');
  if (!plausible) warnings.push('The number has the wrong length for its country, so it may be spoofed or mistyped.');
  return { country: name, iso2: iso, plausible, lineType, warnings };
}

interface Numverify { valid?: boolean; country_code?: string; country_name?: string; location?: string; carrier?: string; line_type?: string | null; success?: boolean; error?: { info?: string } }

export async function phoneCheck(ctx: Ctx, input: string, opts: { country?: string } = {}): Promise<ModuleResult<PhoneCheck>> {
  const n = toE164(input, opts.country);
  if (!n) throw new Error(/^\+|^00/.test(input.trim()) || opts.country ? `not a phone number: ${input}` : 'give the number in international format, e.g. +44 20 7946 0958, or pass a country');
  const off = offlinePhone(n.digits, n.code);
  const provenance: Provenance[] = [{ source: 'calling-codes', url: '', status: 'LIVE', fetchedAt: new Date().toISOString(), note: 'offline ITU calling-code table' }];
  let valid: boolean | null = null;
  let carrier: string | null = null;
  let location: string | null = null;
  let lineType = off.lineType;
  let iso2 = off.iso2;
  const k = key('NUMVERIFY_API_KEY');
  if (!k) provenance.push({ source: 'numverify', url: '', status: 'UNAVAILABLE', fetchedAt: new Date().toISOString(), note: 'set NUMVERIFY_API_KEY to enable carrier and line type' });
  else {
    // The free Numverify plan is HTTP only.
    const r = await ctx.http.get<Numverify>(`http://apilayer.net/api/validate?access_key=${encodeURIComponent(k)}&number=${n.digits}`, { source: 'numverify', ttlSec: 30 * 86_400, retries: 1 });
    if (r.data && r.data.success !== false && typeof r.data.valid === 'boolean') {
      provenance.push(r.prov);
      valid = r.data.valid;
      carrier = r.data.carrier || null;
      location = r.data.location && r.data.location.toLowerCase() !== (off.country ?? '').toLowerCase() ? r.data.location : null;
      lineType = r.data.line_type || lineType;
      if (r.data.country_code) iso2 = r.data.country_code;
    } else provenance.push(r.data?.error ? { ...r.prov, status: 'ERROR', note: r.data.error.info ?? 'lookup failed' } : r.prov);
  }
  const warnings = [...off.warnings];
  if (valid === false) warnings.unshift('Numverify says this number is not valid: it is probably spoofed or made up.');
  if (lineType && /voip/i.test(lineType)) warnings.push('A VoIP number: it can be created online in minutes, anywhere in the world. Scammers often use them.');
  if (lineType && /special|premium|shared/i.test(lineType) && !warnings.some((w) => /premium/.test(w))) warnings.push(`Line type "${lineType}": calling it may cost extra.`);
  const risk: PhoneCheck['risk'] = warnings.some((w) => /one ring|premium|not valid|personal numbers|\+979/.test(w)) ? 'high' : warnings.length ? 'medium' : 'low';
  const advice = risk === 'low'
    ? ['Nothing unusual about the number itself. Scammers can still spoof any number, so judge the message, not only the sender.']
    : ['Do not call back or reply. If the message claims to be from a company you use, contact it through its app or official website.', 'Block the number and report the message (forward scam SMS to 7726 in the US and UK).'];
  return {
    module: 'phone',
    input: `+${n.digits}`,
    generatedAt: ctx.now().toISOString(),
    result: { e164: `+${n.digits}`, countryCode: `+${n.code}`, country: off.country, iso2, plausible: off.plausible, lineType, carrier, location, valid, risk, warnings, advice },
    signals: [],
    provenance,
  };
}
