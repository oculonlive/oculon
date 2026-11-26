/**
 * "I got scammed" rescue: what to do in the next 10 minutes, today and this week, for each kind of scam,
 * and where to report it, by country. Everything here is fixed content held as data; nothing is fetched.
 * Every reporting link was opened with curl on LINKS_CHECKED and answered 200 after redirects. Official
 * services whose sites refused automated requests are named in the text of a verified page that points to
 * them, never linked unchecked.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult } from '../core/types.js';

export const LINKS_CHECKED = '2026-11-26';

export type Phase = 'now' | 'today' | 'week';
export type ReportKind = 'fraud' | 'phishing' | 'identity' | 'cyber' | 'crypto';

export interface ToolLink { label: string; href: string }
export interface Step { id: string; phase: Phase; text: string; tool?: ToolLink }
export interface Situation { id: string; title: string; summary: string; reports: ReportKind[]; steps: Step[] }
export interface ReportLink { name: string; url: string; what: string; phone?: string; kinds: ReportKind[] }
export interface Country { code: string; name: string; reports: ReportLink[]; note?: string }

export const PHASES: { id: Phase; label: string }[] = [
  { id: 'now', label: 'In the next 10 minutes' },
  { id: 'today', label: 'Today' },
  { id: 'week', label: 'This week' },
];

const T = {
  guard: { label: 'Wallet Guard: see and revoke approvals', href: '/guard' },
  checkup: { label: 'Security Checkup: password and breach check', href: '/checkup' },
  url: { label: 'URL check (Investigate, kind URL)', href: '/app#investigate' },
  address: { label: 'Address check (Investigate, kind address)', href: '/app#investigate' },
  spot: { label: 'Spot the Scam: daily practice', href: '/spot' },
};

/** Steps shared by several situations, so the merged checklist lists each one once. */
const S = {
  record: { id: 'record', phase: 'today', text: 'Write down what happened while you remember it: dates, times, amounts, the website or number, and screenshots of the messages. Keep the messages; do not delete the chat.' },
  report: { id: 'report', phase: 'today', text: 'Report it to the services listed below for your country. A report with a reference number helps your bank, your exchange and the police.' },
  recovery: { id: 'recovery-scam', phase: 'week', text: 'Expect "recovery" offers. Anyone who contacts you promising to get the money back for a fee, including people posing as police, lawyers or blockchain investigators, is running a second scam.' },
  bank: { id: 'call-bank', phase: 'now', text: 'Call your bank or card issuer now, on the number printed on your card or shown in its app, not one from a message. Say it is fraud and ask them to stop or recall the payment and block the card or account.' },
  changePw: { id: 'change-password', phase: 'now', text: 'Change that password now, on the real site or app: type the address yourself or open the app, never use a link from the message. If you used the same password anywhere else, change it there too.' },
  sessions: { id: 'sign-out', phase: 'now', text: 'In the account security settings, sign out of all other sessions and devices.' },
  accountReview: { id: 'account-review', phase: 'today', text: 'Check the account for changes the scammer may have made: recovery email and phone, unknown devices, mail forwarding or filter rules, linked apps, and saved payment methods. Remove anything you do not recognise.' },
  twoFa: { id: 'two-factor', phase: 'today', text: 'Turn on two-step sign-in with an authenticator app, a passkey or a security key. Text-message codes are better than nothing but can be stolen by SIM swap.' },
  breachCheck: { id: 'breach-check', phase: 'today', text: 'Check whether the password is in known breach lists. The check hashes it in your browser and never sends it.', tool: T.checkup },
  manager: { id: 'password-manager', phase: 'week', text: 'Move to a password manager and give every account its own password. A password manager also refuses to fill in a password on a look-alike site.' },
  simLock: { id: 'sim-lock', phase: 'today', text: 'Ask your mobile carrier for a SIM or port-out lock (a PIN needed before your number can be moved), so a scammer cannot take over your number.' },
  newWallet: { id: 'new-wallet', phase: 'now', text: 'Create a brand-new wallet with a new recovery phrase, on a device you trust, and move whatever is left to it right away: tokens, NFTs and anything staked. Do not import the old phrase anywhere.' },
  txHashes: { id: 'tx-hashes', phase: 'today', text: 'Save the transaction hashes, your address and the scammer\'s address. Reports to the police and to exchanges need them.', tool: T.address },
  scan: { id: 'scan-device', phase: 'today', text: 'Run a full scan with the security software built into your device (for example Microsoft Defender on Windows), and install pending system updates.' },
  reportLink: { id: 'report-link', phase: 'today', text: 'Report the phishing site so browsers start warning other people (Google Safe Browsing link below), and to your country\'s service for scam websites if it has one.' },
  creditFreeze: { id: 'credit-freeze', phase: 'today', text: 'Where your country has credit bureaus, place a fraud alert or credit freeze so no one can open credit in your name. In the US the IdentityTheft.gov plan below walks you through it.' },
  watchStatements: { id: 'watch-statements', phase: 'week', text: 'Watch bank and card statements, and your credit report where available, for charges or accounts you do not recognise, for the next few months.' },
  stopPaying: { id: 'stop-paying', phase: 'now', text: 'Do not send any more money, even if you are told it is a fee, a tax or a deposit needed to release the first payment or a withdrawal.' },
  warnContacts: { id: 'warn-contacts', phase: 'today', text: 'Tell your contacts that your account was taken over and that any message asking for money, codes or a click was not from you.' },
} satisfies Record<string, Step>;

export const SITUATIONS: Situation[] = [
  {
    id: 'link', title: 'I clicked a link', summary: 'You opened a link from a message but did not type anything in.', reports: ['phishing'],
    steps: [
      { id: 'close-page', phase: 'now', text: 'Close the page. Do not type anything into it, and do not allow notifications or downloads it asks for.' },
      { id: 'delete-download', phase: 'now', text: 'If a file downloaded, do not open it. Delete it, then empty the trash or downloads folder.' },
      { id: 'check-link', phase: 'today', text: 'Check the link to see what it was. Paste it as text; do not open it again.', tool: T.url },
      S.scan, S.reportLink,
      { id: 'expect-followup', phase: 'week', text: 'Expect follow-up messages. A scammer who got a click often tries again with a more convincing story.', tool: T.spot },
    ],
  },
  {
    id: 'password', title: 'I typed a password into a site', summary: 'You entered a password on a page that may have been fake.', reports: ['phishing', 'cyber'],
    steps: [S.changePw, S.sessions, S.accountReview, S.twoFa, S.breachCheck, S.reportLink, S.manager],
  },
  {
    id: 'code', title: 'I gave someone a one-time code', summary: 'You read out or typed a code sent by text, email or an app.', reports: ['fraud', 'cyber'],
    steps: [
      { id: 'code-meaning', phase: 'now', text: 'A one-time code lets someone sign in, reset a password or approve a payment. Contact the service the code came from right away, through its app or official website.' },
      S.bank, S.changePw, S.sessions, S.accountReview, S.simLock, S.twoFa, S.record, S.report,
    ],
  },
  {
    id: 'seed', title: 'I shared my seed phrase or private key', summary: 'Someone has your wallet recovery phrase or a private key.', reports: ['crypto', 'fraud'],
    steps: [
      { id: 'wallet-lost', phase: 'now', text: 'Treat the wallet as lost. Whoever has the phrase controls every account made from it, and nothing can change that phrase.' },
      S.newWallet,
      { id: 'all-accounts', phase: 'now', text: 'Move funds out of every account created from the same phrase, on every chain, not only the one that was drained.' },
      { id: 'no-revoke-help', phase: 'today', text: 'Revoking approvals does not protect a wallet whose key is known: the scammer can sign anything. Moving funds is the only fix.' },
      S.txHashes, S.record, S.report, S.recovery,
    ],
  },
  {
    id: 'signed', title: 'I signed a wallet transaction or approval', summary: 'A site asked you to connect and sign, and now you are not sure what you approved.', reports: ['crypto', 'fraud'],
    steps: [
      { id: 'revoke', phase: 'now', text: 'Check which contracts can still move your tokens and revoke the ones you do not know, especially unlimited approvals and NFT "approve all". Revoking costs a small network fee.', tool: T.guard },
      { id: 'move-valuables', phase: 'now', text: 'If you signed an off-chain permit, it may not show as an approval until the scammer uses it. Moving valuable tokens to a fresh wallet is the safest step.' },
      { id: 'disconnect-site', phase: 'today', text: 'Disconnect the site in your wallet\'s connected sites list, and clear the browser tab.' },
      S.txHashes, S.report,
      { id: 'burner-wallet', phase: 'week', text: 'Use a separate wallet with small amounts for new sites and mints, and keep savings in a wallet that never connects to unknown sites, ideally a hardware wallet.' },
      S.recovery,
    ],
  },
  {
    id: 'card', title: 'I gave my card details', summary: 'You entered your card number, expiry or security code on a site or told someone over the phone.', reports: ['fraud', 'phishing'],
    steps: [
      S.bank,
      { id: 'freeze-card', phase: 'now', text: 'Freeze or lock the card in your banking app if it has that option, while you wait to get through.' },
      { id: 'dispute', phase: 'today', text: 'Go through recent transactions with the bank and dispute every one you did not make. Ask for a new card number.' },
      S.record, S.report, S.watchStatements,
    ],
  },
  {
    id: 'bank', title: 'I sent a bank transfer', summary: 'You paid money by bank transfer to someone who turned out to be a scammer.', reports: ['fraud'],
    steps: [
      S.bank,
      { id: 'recall-fast', phase: 'now', text: 'Speed matters: banks can sometimes freeze money still sitting in the receiving account. Give them the amount, time and the account you paid.' },
      S.record, S.report,
      { id: 'reimbursement', phase: 'today', text: 'Ask your bank whether you are covered by a reimbursement scheme for scam payments in your country, and write down the case number they give you.' },
      S.stopPaying,
      S.recovery,
    ],
  },
  {
    id: 'crypto', title: 'I sent crypto', summary: 'You sent coins or tokens to a scammer, or to an investment site that will not pay out.', reports: ['crypto', 'fraud'],
    steps: [
      { id: 'exchange-support', phase: 'now', text: 'If you sent it from an exchange, contact that exchange\'s support through its app now. If the scammer\'s address belongs to an exchange, a police report can lead that exchange to freeze the funds.' },
      S.stopPaying,
      S.txHashes, S.record, S.report, S.recovery,
    ],
  },
  {
    id: 'remote', title: 'I installed an app or gave remote access', summary: 'Someone talked you into installing software or letting them control your computer or phone.', reports: ['fraud', 'cyber'],
    steps: [
      { id: 'disconnect', phase: 'now', text: 'Disconnect the device from the internet (turn off Wi-Fi and mobile data) to end the session.' },
      { id: 'uninstall', phase: 'now', text: 'Uninstall the remote access or other app they asked for. On a phone, also remove any app you do not recognise and check which apps have accessibility or device administrator rights.' },
      { id: 'other-device', phase: 'now', text: 'From a different device you trust, change the passwords of your email and banking, starting with email.' },
      S.bank, S.scan, S.record, S.report,
      { id: 'reset-device', phase: 'week', text: 'If you are not sure the device is clean, back up your files, reset it to factory settings and reinstall apps from the official store.' },
      S.recovery,
    ],
  },
  {
    id: 'id', title: 'I sent ID documents or selfies', summary: 'You sent a passport, driving licence, ID card or a selfie holding one.', reports: ['identity', 'fraud'],
    steps: [
      { id: 'list-sent', phase: 'now', text: 'Write down exactly which documents and photos you sent, to whom and when.' },
      { id: 'issuer', phase: 'today', text: 'Contact the office that issued the document and ask whether it should be reported as compromised or replaced.' },
      S.creditFreeze, S.report, S.watchStatements,
      { id: 'mail-watch', phase: 'week', text: 'Watch for letters, emails or calls about accounts, loans or phone contracts you did not open, and act on them straight away.' },
    ],
  },
  {
    id: 'takeover', title: 'My account was taken over', summary: 'You cannot sign in, or someone is posting or messaging as you.', reports: ['cyber', 'identity'],
    steps: [
      { id: 'official-recovery', phase: 'now', text: 'Use the service\'s official account recovery, from its app or by typing its address. Never use a "recovery" helper who contacts you.' },
      { id: 'email-first', phase: 'now', text: 'If your email was taken, secure it first: it can reset every other account.' },
      S.warnContacts, S.sessions, S.accountReview, S.twoFa, S.breachCheck, S.report, S.manager,
    ],
  },
];

const SAFE_BROWSING: ReportLink = { name: 'Google Safe Browsing', url: 'https://safebrowsing.google.com/safebrowsing/report_phish/', what: 'Report a phishing website so Chrome, Firefox and Safari start warning visitors.', kinds: ['phishing'] };
const ECONSUMER: ReportLink = { name: 'econsumer.gov', url: 'https://econsumer.gov/', what: 'Report online scams involving businesses in another country (run by consumer protection agencies from over 60 countries).', kinds: ['fraud', 'crypto', 'phishing'] };
const EUROPOL: ReportLink = { name: 'Europol: report cybercrime online', url: 'https://www.europol.europa.eu/report-a-crime/report-cybercrime-online', what: 'Links to the police reporting service of each EU member state.', kinds: ['fraud', 'cyber', 'crypto', 'identity'] };

export const COUNTRIES: Country[] = [
  {
    code: 'US', name: 'United States', reports: [
      { name: 'FTC ReportFraud', url: 'https://reportfraud.ftc.gov/', what: 'Report scams, fraud and bad business practices to the Federal Trade Commission.', kinds: ['fraud', 'phishing', 'crypto'] },
      { name: 'FBI Internet Crime Complaint Center (IC3)', url: 'https://www.ic3.gov/', what: 'Report internet crime, including crypto and investment scams, to the FBI. Include transaction hashes and addresses.', kinds: ['fraud', 'cyber', 'crypto'] },
      { name: 'IdentityTheft.gov', url: 'https://www.identitytheft.gov/', what: 'Report identity theft and get a step-by-step recovery plan, including credit freezes.', kinds: ['identity'] },
      { name: 'USA.gov: where to report scams', url: 'https://www.usa.gov/where-report-scams', what: 'Which federal or state agency handles each kind of scam.', kinds: ['fraud', 'phishing', 'identity', 'cyber', 'crypto'] },
      SAFE_BROWSING,
    ],
  },
  {
    code: 'GB', name: 'United Kingdom', reports: [
      { name: 'GOV.UK: report scams and phishing', url: 'https://www.gov.uk/report-suspicious-emails-websites-phishing', what: 'The official guide to reporting. If you lost money or were hacked in England or Wales, it directs you to Report Fraud (online, or 0300 123 2040). In Scotland, report to Police Scotland.', phone: '0300 123 2040 (Report Fraud, England and Wales)', kinds: ['fraud', 'phishing', 'cyber', 'crypto', 'identity'] },
      { name: 'NCSC: report a scam email', url: 'https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email', what: 'Forward scam emails to report@phishing.gov.uk. Forward scam text messages to 7726 (free).', kinds: ['phishing'] },
      { name: 'NCSC: report a scam website', url: 'https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-website', what: 'Report a fake website so it can be taken down.', kinds: ['phishing'] },
      { name: 'Police Scotland: contact us', url: 'https://www.scotland.police.uk/contact-us/', what: 'In Scotland, report a fraud or scam to Police Scotland (101, or 999 in an emergency).', phone: '101', kinds: ['fraud', 'cyber', 'crypto', 'identity'] },
      { name: 'Cifas', url: 'https://www.cifas.org.uk/', what: 'The UK fraud prevention service; offers Protective Registration if your identity documents were stolen.', kinds: ['identity'] },
      SAFE_BROWSING,
    ],
  },
  {
    code: 'CA', name: 'Canada', reports: [
      { name: 'Canadian Anti-Fraud Centre: report', url: 'https://antifraudcentre-centreantifraude.ca/report-signalez-eng.htm', what: 'Report fraud and cybercrime online. When checked, the page said its toll-free line was unavailable and asked people to report online.', kinds: ['fraud', 'phishing', 'crypto', 'identity', 'cyber'] },
      { name: 'Canadian Centre for Cyber Security', url: 'https://www.cyber.gc.ca/en/incident-management', what: 'Report a cyber incident to the federal cyber security centre.', kinds: ['cyber'] },
      SAFE_BROWSING,
    ],
    note: 'Also report to your local police and get a file number.',
  },
  {
    code: 'AU', name: 'Australia', reports: [
      { name: 'Australian Federal Police: cybercrime', url: 'https://www.afp.gov.au/crimes/cybercrime', what: 'Explains where to report: cybercrime goes to ReportCyber (Australian Cyber Security Centre), and scam reports can also go to the ACCC\'s Scamwatch.', kinds: ['fraud', 'cyber', 'crypto', 'phishing'] },
      { name: 'IDCARE', url: 'https://www.idcare.org/', what: 'Free national identity and cyber support service for Australia and New Zealand. Individual helpline 1800 595 160.', phone: '1800 595 160', kinds: ['identity', 'cyber', 'fraud'] },
      SAFE_BROWSING,
    ],
    note: 'ReportCyber (cyber.gov.au) and Scamwatch (scamwatch.gov.au) did not answer automated checks, so they are named rather than linked; type their addresses into your browser.',
  },
  {
    code: 'NZ', name: 'New Zealand', reports: [
      { name: 'NCSC New Zealand: report', url: 'https://www.ncsc.govt.nz/report/', what: 'Report a scam or cyber security problem to the National Cyber Security Centre.', kinds: ['cyber', 'phishing', 'fraud', 'crypto'] },
      { name: 'Netsafe', url: 'https://netsafe.org.nz/', what: 'Online safety help and reporting of online harm and scams.', kinds: ['fraud', 'phishing'] },
      { name: 'IDCARE', url: 'https://www.idcare.org/', what: 'Free identity and cyber support service for Australia and New Zealand.', kinds: ['identity'] },
      SAFE_BROWSING,
    ],
  },
  {
    code: 'IE', name: 'Ireland', reports: [
      { name: 'An Garda Siochana: fraud', url: 'https://www.garda.ie/en/crime/fraud/', what: 'Fraud advice from the Irish police; report to your local Garda station.', kinds: ['fraud', 'cyber', 'crypto', 'identity', 'phishing'] },
      EUROPOL, SAFE_BROWSING,
    ],
  },
  {
    code: 'FR', name: 'France', reports: [
      { name: 'Cybermalveillance.gouv.fr', url: 'https://www.cybermalveillance.gouv.fr/', what: 'The national assistance service for victims of cyber attacks and scams (in French).', kinds: ['cyber', 'fraud', 'phishing', 'crypto'] },
      { name: 'PHAROS (internet-signalement.gouv.fr)', url: 'https://www.internet-signalement.gouv.fr/', what: 'The government platform for reporting illegal online content, including scam sites (in French).', kinds: ['phishing', 'fraud'] },
      EUROPOL, SAFE_BROWSING,
    ],
  },
  {
    code: 'NL', name: 'Netherlands', reports: [
      { name: 'Fraudehelpdesk', url: 'https://www.fraudehelpdesk.nl/', what: 'The national fraud help desk: advice and reports of fraud (in Dutch). Phone 088 786 7372.', phone: '088 786 7372', kinds: ['fraud', 'phishing', 'crypto', 'identity'] },
      EUROPOL, SAFE_BROWSING,
    ],
  },
  {
    code: 'ES', name: 'Spain', reports: [
      { name: 'INCIBE cyber security helpline (017)', url: 'https://www.incibe.es/linea-de-ayuda-en-ciberseguridad', what: 'The national cyber security helpline: free and confidential advice by phone on 017 (in Spanish).', phone: '017', kinds: ['cyber', 'fraud', 'phishing', 'identity', 'crypto'] },
      EUROPOL, SAFE_BROWSING,
    ],
  },
  {
    code: 'SG', name: 'Singapore', reports: [
      { name: 'ScamShield', url: 'https://www.scamshield.gov.sg/', what: 'The national anti-scam service. Call the 24/7 ScamShield Helpline on 1799 if you are unsure.', phone: '1799', kinds: ['fraud', 'phishing', 'crypto', 'identity', 'cyber'] },
      SAFE_BROWSING,
    ],
  },
  { code: 'EU', name: 'Other EU country', reports: [EUROPOL, ECONSUMER, SAFE_BROWSING] },
  { code: 'OTHER', name: 'Somewhere else', reports: [ECONSUMER, SAFE_BROWSING], note: 'Report to your local police and your bank as well, and ask for a reference number.' },
];

export interface PlanStep extends Step { situations: string[] }
export interface RescuePlan {
  situations: { id: string; title: string; summary: string }[];
  countries: { code: string; name: string }[];
  selected: string[];
  country: string | null;
  checklist: { phase: Phase; label: string; steps: PlanStep[] }[];
  reports: ReportLink[];
  countryNote: string | null;
  linksChecked: string;
  note: string;
}

const ALIASES: Record<string, string> = { UK: 'GB', USA: 'US', GBR: 'GB', AUS: 'AU', CAN: 'CA', NZL: 'NZ' };

export function findCountry(code?: string | null): Country | null {
  if (!code?.trim()) return null;
  const c = code.trim().toUpperCase();
  return COUNTRIES.find((x) => x.code === (ALIASES[c] ?? c)) ?? null;
}

/** Merge the chosen situations into one checklist (each step once, in phase order) and pick the reporting links. */
export function buildPlan(situation?: string | string[] | null, country?: string | null): RescuePlan {
  const ids = (Array.isArray(situation) ? situation : String(situation ?? '').split(','))
    .map((s) => s.trim().toLowerCase()).filter(Boolean);
  const unknown = ids.filter((i) => !SITUATIONS.some((s) => s.id === i));
  if (unknown.length) throw new Error(`unknown situation: ${unknown.join(', ')}. Pick from ${SITUATIONS.map((s) => s.id).join(', ')}`);
  const chosen = SITUATIONS.filter((s) => ids.includes(s.id));
  const merged = new Map<string, PlanStep>();
  for (const s of chosen) for (const st of s.steps) {
    const have = merged.get(st.id);
    if (have) { if (!have.situations.includes(s.id)) have.situations.push(s.id); }
    else merged.set(st.id, { ...st, situations: [s.id] });
  }
  if (chosen.length && !merged.has('report')) merged.set('report', { ...S.report, situations: chosen.map((s) => s.id) });
  const all = [...merged.values()];
  const c = findCountry(country);
  if (country?.trim() && !c) throw new Error(`unknown country: ${country}. Pick from ${COUNTRIES.map((x) => x.code).join(', ')}`);
  const kinds = new Set(chosen.flatMap((s) => s.reports));
  const reports = c ? c.reports.filter((r) => !kinds.size || r.kinds.some((k) => kinds.has(k))) : [];
  return {
    situations: SITUATIONS.map(({ id, title, summary }) => ({ id, title, summary })),
    countries: COUNTRIES.map(({ code, name }) => ({ code, name })),
    selected: chosen.map((s) => s.id),
    country: c?.code ?? null,
    checklist: PHASES.map((p) => ({ phase: p.id, label: p.label, steps: all.filter((s) => s.phase === p.id) })),
    reports,
    countryNote: c?.note ?? null,
    linksChecked: LINKS_CHECKED,
    note: 'General guidance, not legal or financial advice. If you are in danger or being threatened, call your local emergency number.',
  };
}

export async function rescuePlan(ctx: Ctx, situation?: string | string[], country?: string): Promise<ModuleResult<RescuePlan>> {
  const plan = buildPlan(situation, country);
  return {
    module: 'rescue',
    input: [plan.selected.join(',') || 'all', plan.country ?? ''].filter(Boolean).join(' · '),
    generatedAt: ctx.now().toISOString(),
    result: plan,
    signals: [],
    provenance: [{ source: 'oculon-rescue', url: 'https://oculon.live/rescue', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: `fixed guidance; reporting links checked ${LINKS_CHECKED}` }],
  };
}
