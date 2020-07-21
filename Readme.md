# Saviynt Security Manager API Powershell Module (SSMAPIPS)

SSMAPIPS is a Powershell module that facilitates interaction with a limited set of Saviynt SSM APIs. Their full API reference document is linked at https://saviynt.com/api-reference/. 

### Installation & Usage

- `import-module SSMAPIPS.psm1`
- `Connect-SSMService -Hostname <FQDN of your tenant> -Username <username> -Password <password>`

### Capabilities
- Connect-SSMService: Establish credentials for the module
- Disconnect-SSMService: Remove credentials and token cache
- Get-SSMRole
- Get-SSMEntitlement
- Get-SSMEndpoint
- Get-SSMTask
- Get-SSMTaskDetail
- Get-SSMUser
- Get-SSMAccount
- Get-SSMSavRole
- Update-SSMUser
- Update-SSMAccount
- Complete-SSMTask

### Development

This module was written to facilite production operations at Washington University in St. Louis and is maintained with that team's desired needs in mind. Feel free to copy and modify this module as needed or submit code feedback and I'll try to incorperate it. I'm not an application developer by trade, so don't judge my code. :) This module provides read-only API integration at the time of creation. Eventually, I hope to expand into modification of data also.

### Todos

 - Add more API endpoints
 - Write tests to prevent breaking changes by Saviynt (Vendor)
 - Add read-write integrations

### License as an MIT License

Copyright (c) 2019 Ken Koch @ Washington University in St. Louis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
