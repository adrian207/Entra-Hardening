# License

## MIT License

Copyright (c) 2025 Entra ID Hardening Scripts Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.**

---

## Disclaimer

### Important Security Notice

These scripts make significant changes to your Microsoft Entra ID (Azure AD) tenant's security configuration. While they implement security best practices based on Microsoft's official guidance, you should:

1. **Test Thoroughly**: Always test in a non-production environment first
2. **Review Changes**: Understand what each script does before running it
3. **Backup Configuration**: Document your current settings before making changes
4. **Have Rollback Plan**: Ensure you have emergency access (break-glass accounts) configured
5. **Monitor Impact**: Review logs and user feedback after deployment
6. **Understand Risk**: You are responsible for the security of your environment

### No Warranty or Guarantee

The authors and contributors of this project:

- Make no warranties about the effectiveness of these security controls
- Cannot guarantee protection against all security threats
- Are not responsible for any service disruptions or data loss
- Do not provide official support (this is a community/reference implementation)

### Microsoft Official Documentation

These scripts are based on Microsoft's published security guidance as of October 2025. Always refer to the official Microsoft documentation for the most current recommendations:

- [Microsoft Entra Documentation](https://learn.microsoft.com/en-us/entra/)
- [Conditional Access Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
- [Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/)

### Use at Your Own Risk

By using these scripts, you acknowledge that:

- You have tested them in a non-production environment
- You understand the changes they will make
- You have appropriate backups and rollback procedures
- You accept full responsibility for any consequences of their use
- You will monitor and maintain the configurations over time

### Professional Services

For production deployments in critical environments, consider:

- Engaging Microsoft Consulting Services
- Working with a Microsoft Partner
- Hiring certified security professionals
- Conducting formal security assessments

### Compliance and Regulatory Requirements

These scripts implement general security best practices but may not meet all requirements for:

- Industry-specific regulations (HIPAA, PCI-DSS, etc.)
- Geographic data residency requirements
- Specific compliance frameworks (SOC 2, ISO 27001, etc.)
- Organizational security policies

Consult with your compliance team before deployment.

### Support

This is a reference implementation and community project. Support is provided on a best-effort basis through:

- Documentation in this repository
- Community discussions (if applicable)
- Your organization's internal support channels

For official Microsoft support, contact Microsoft directly through your support agreement.

---

## Third-Party Dependencies

This project relies on:

- **Microsoft Graph PowerShell SDK** - [License](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/dev/LICENSE.txt)
- **Azure PowerShell Modules** - [License](https://github.com/Azure/azure-powershell/blob/main/LICENSE.txt)

These dependencies have their own licenses and terms of use.

---

## Contribution License

By contributing to this project, you agree that your contributions will be licensed under the same MIT License that covers this project.

---

**Last Updated:** October 22, 2025

