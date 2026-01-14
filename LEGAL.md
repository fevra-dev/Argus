# Legal and Ethical Guidelines for Argus (Canada)

## Summary

**Yes, you can legally test Argus on your own network and equipment in Canada.**

## Canadian Law - Computer Misuse

### Relevant Legislation

**Criminal Code Section 342.1 - Unauthorized use of computer:**

> "Every person who, fraudulently and without colour of right, obtains, directly or indirectly, any computer service... is guilty of an indictable offence..."

### What This Means

✅ **LEGAL:**
- Testing on networks you own
- Testing on devices you own
- Testing with **explicit written authorization**
- Testing in isolated lab environments
- Testing your own home network

❌ **ILLEGAL:**
- Testing networks without permission
- Testing systems owned by others (even if "for their benefit")
- Accessing data beyond authorization
- Continuing after being told to stop

## When Authorization is Required

### You DON'T Need Authorization For:
- Your home network (you own it)
- Your own devices (routers, IoT devices, etc.)
- Isolated test networks you control
- Virtual machines and containers you created

### You DO Need Authorization For:
- Work networks (even if you work there)
- University/school networks
- Public networks (coffee shops, hotels, etc.)
- Neighbors' networks
- Client networks (unless explicitly authorized)
- Cloud infrastructure you don't own

## Getting Proper Authorization

### Written Authorization Should Include:
1. **Clear scope**: What networks/devices can be tested
2. **Timeframe**: When testing is authorized
3. **Purpose**: Why testing is being done
4. **Contact**: Who authorized it and how to reach them
5. **Limitations**: Any restrictions or exclusions

### Example Authorization Letter:
```
[Date]

Authorization for Security Testing

I, [Name], as [Title] of [Organization], authorize [Your Name] 
to perform security testing using Argus on the following 
network resources:

- Network: [IP Range or Network Name]
- Timeframe: [Start Date] to [End Date]
- Purpose: Security assessment and vulnerability identification

Signed,
[Authorized Person]
[Date]
```

## Best Practices

### 1. Document Everything
- Keep authorization letters
- Log what you tested and when
- Record findings appropriately

### 2. Use Isolated Environments
- Create separate VLANs for testing
- Use virtual machines
- Test on non-production systems

### 3. Be Transparent
- Inform users if testing on shared networks
- Provide findings reports to authorized parties
- Follow responsible disclosure if vulnerabilities found

### 4. Respect Privacy
- Don't access data beyond testing scope
- Don't collect or store sensitive information
- Follow data protection laws (PIPEDA in Canada)

### 5. Stop When Asked
- Immediately stop if authorization is revoked
- Respect network owner requests
- Remove any tools/probes if requested

## Home Lab Testing

### Safe Home Network Testing:
```
✅ Your home router (192.168.x.x range you control)
✅ IoT devices you own
✅ Personal servers/computers
✅ Virtual machines on your network
✅ Isolated test VLAN
```

### Be Cautious About:
```
⚠️ Shared networks (roommates, family)
⚠️ ISP equipment (you may not fully own it)
⚠️ Neighbors' devices (if on shared network)
```

## Work/Professional Context

### For Security Professionals:
- Always get written authorization
- Use professional liability insurance
- Follow industry standards (OWASP, PTES)
- Maintain certifications (CEH, OSCP, etc.)
- Document methodology

### For Bug Bounty:
- Only test programs you're authorized for
- Follow program rules strictly
- Don't test beyond scope
- Report responsibly

## Penalties (Canada)

Violations can result in:
- Up to 10 years imprisonment
- Criminal record
- Civil liability
- Professional consequences

## Responsible Disclosure

If you find vulnerabilities:

1. **Document** the finding
2. **Notify** the owner/authorized contact
3. **Allow reasonable time** for patching
4. **Don't exploit** beyond testing
5. **Don't publicly disclose** until fixed

## Useful Resources

- **Canadian Criminal Code**: https://laws-lois.justice.gc.ca
- **PIPEDA** (Privacy): https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Legal Consultation**: Consult a lawyer for specific questions

## Disclaimer

**This document provides general information only and does not constitute legal advice.** 

- Laws can vary by province/territory
- Legal interpretations can change
- Specific situations may have unique considerations
- Always consult a qualified lawyer for legal questions

The authors and contributors of Argus are not responsible for misuse of this tool or violations of law.

