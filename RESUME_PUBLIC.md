# TIER 1 — PUBLIC VERSION

**Safe to post:** LinkedIn, personal site, GitHub profile, public PDF.
**No phone. No street address. No availability date. No system-level government architecture detail.**
Full versions (sent to named people on request): [SAP](RESUME_SAP_SECURITY_IDENTITY.md) ·
[Identity/AI](RESUME_IDENTITY_AI.md)

---

# Serguei Fedotov

**Identity & Access Security Architect · SAP Security & IAM · Identity and Policy for AI Systems**

Ottawa, Ontario, Canada · [professional email] · [LinkedIn URL]
Available for contract engagements — Canada / North America remote

---

## SUMMARY

Security architect with 20+ years building the layer that decides what an identity is allowed to reach:
single sign-on and federation, identity governance, privileged access, and the formal security
assessments that get systems authorized to operate. Delivered across federal departments and large
regulated enterprises. Hands-on — I architect and implement.

Now extending the same specialization to AI systems: identity-based authorization on retrieval, and
policy enforcement on agent and SIEM tool calls.

---

## CORE SKILLS

**Identity federation** — SAML 2.0 · OAuth 2.0 · OIDC · ForgeRock (OpenAM, OpenDJ, OpenIDM, OpenIG) ·
Okta · Keycloak · PingIdentity · ADFS · Azure AD / Entra ID · Oracle Access Manager & Identity Manager ·
Shibboleth · IdP proxies · attribute mapping · Levels of Assurance

**Identity governance & privileged access** — SailPoint IdentityIQ · CyberArk PAM · ICAM strategy ·
Zero Trust Architecture · MFA · automated provisioning · PKI / X.509

**SAP security & identity** — SAP Identity Authentication Service (IAS) · Identity & Access Governance
(IAG) · Identity Provisioning Service · SAP Single Sign-On · SAP Enterprise Threat Detection (ETD) ·
**SAP BTP** (application deployment, service configuration) · SAP IBP · SAP Analytics Cloud ·
S/4HANA Cloud · SAP ECC · CI-DS · Netweaver ABAP & Java · role and authorization design

**Security assessment & authorization** — ITSG-33 · ITSP-50 · NIST · FedRAMP · Threat & Risk Assessment ·
Security Concept of Operations · Business Continuity & Disaster Recovery · security architecture
documentation

**Detection & monitoring** — Azure Sentinel · Elasticsearch / Logstash / Kibana · Suricata IDS/IPS ·
Kafka · Spark · Flink · Prometheus · Grafana

**Engineering** — Python · FastAPI · Java / Spring Boot · React · Angular · Node.js · Golang · Docker ·
Helm · PostgreSQL · Neo4j · Redis · Elasticsearch · REST · OData · GraphQL · SOAP / WS-Security

**AI security** — retrieval authorization · agent and MCP tool policy · LangChain · LangGraph ·
vector stores (Qdrant, pgvector) · air-gapped / local model deployment

---

## PROJECTS

**Marifort Gate** — identity-enforced security gateway for AI retrieval · Python / FastAPI ·
github.com/marifort/rag-protection
Enforces identity-provider group membership as a pre-retrieval authorization filter on vector stores, so
documents a user is not entitled to never enter a language model's candidate set. Input and output
guardrails, a decision audit trail on every call, and SIEM export. Docker and Helm deployment, operator
console, test suite and CI.

**SOC Governance** — govern what an AI may do to a SIEM · Python / FastAPI ·
github.com/sergueifedotov/soc-governance
Adds the missing layer around MCP-driven SIEM actions: policy on who may call which tool with
which arguments, a human gate before any write, and an audit trail that outlives the call. Built
on a MIT fork of gensecaihq/Wazuh-MCP-Server (v4.2.1). Phase 2: read-only LangChain synthesis with
a deterministic fallback. Phase 3: LangGraph propose → approve → execute (block IP / isolate host
/ quarantine file) — the model is not on the write path. Phase 4: SOC console, incidents, Neo4j,
OpenCTI. Proxy also at github.com/sergueifedotov/mcp-security-proxy.

*Gate decides what an AI may read. SOC Governance decides what an AI may do to a SIEM, and records it.*

---

## EXPERIENCE

**SAP Cloud Solution Architect (Level 3)** — Federal Government of Canada, National Defence · Ottawa ·
2023 – present
Identity federation architecture for SAP cloud services, including an identity-provider proxy with custom
attribute mapping. Identity governance, role management and automated provisioning. SAP BTP application
deployment and service configuration. Security monitoring integrated with SIEM. Coordination of Security
Assessment & Authorization under ITSG-33, ITSP-50, NIST and FedRAMP, with the accompanying security
architecture, threat and risk, and continuity documentation.

**IT Security Design Specialist (Level 3)** — Federal Government of Canada, Shared Services Canada ·
Ottawa · 2023
Security assessment and authorization on a classified project: design review and control gap assessment
against ITSG-33, plus recommendations on a privileged access management design.

**Senior Security Analyst** — Federal Government of Canada, Statistics Canada · Ottawa · 2022 – 2023
Led the Identity, Credential and Access Management security strategy for a hybrid cloud environment with
federated partner subsystems, aligned to Zero Trust, MFA and BYOD. Architecture and requirements for
privileged access management (CyberArk) and identity governance (SailPoint) across cloud, on-premises and
partner systems. Security architecture and standards for cloud tenant subsystems. Product assessments
with vendors and strategy presentations to executives.

**Senior Security Analyst** — Federal Government of Canada, National Defence · Ottawa · 2017 – 2022
SAML proxy and federation architecture across SAP and ForgeRock platforms. Application integration with
OAuth2 / OIDC identity providers including Okta, Keycloak, ForgeRock and Oracle. Security assessment and
authorization under ITSG-33, ITSP-50 and NIST. Deployment of SAP Enterprise Threat Detection. Built a
streaming log-processing and intrusion-detection platform on Kafka, Spark/Flink, Suricata and ELK.

**Lead Engineer** — Xerox Corporation · Ottawa · 2016 – 2018
Architected and implemented an enterprise SAML 2.0 identity federation solution on ForgeRock, including
per-customer attribute mapping plugins. Integrated the service provider with multiple customer identity
providers including PingIdentity, Okta and Tivoli. Threat and risk assessment, disaster recovery
planning, and detection of TLS, OAuth2 and SAML protocol failures.

**Senior Security Consultant** — Federal Government of Canada, Canada School of Public Service · Ottawa ·
2016 – 2017
SAML 2.0 federation across Shibboleth, SimpleSAMLphp and ForgeRock; integration with PingFederate.
Security assessment under ITSG-33 and ITSG-22. Custom cryptographic and directory modules; two-way
identity replication.

**Security Design Specialist** — Federal Government of Canada, Shared Services Canada · Ottawa ·
2014 – 2016
Government credential service integration with client departments. Tailored the ITSG-33 assessment and
authorization profile for an enterprise identity and access management system. Containerized an existing
SSO and SAML federation platform for elastic-cloud deployment; cloud identity service configuration.

**Security Architect** — Federal Government of Canada, Foreign Affairs and International Trade · Ottawa ·
2012 – 2014
Architected a highly available SAML 2.0 single sign-on federation integrated with the Government of
Canada credential federation, including signing, encryption, two-factor authentication and custom Levels
of Assurance. Self-registration with directory reconciliation; adaptive risk authentication.

---

## EARLIER

**SOA Architect** — Bank of Canada · 2010 – 2012 — Custom web services security policies with SAML
assertion, signing and encryption; WS-Security; PKI certificate process; identity manager with directory
replication.

**Technical Solution Architect** — Lockheed Martin · 2009 – 2010 — Clustered XML gateway and enterprise
service bus with mutual TLS, SAML assertions and message-level WS-Security.

**Integration Architect** — Public Works and Government Services Canada · 2007 – 2009 — Technical lead
for an enterprise SOA platform serving 400,000 users of a national pension system; highly available
access management cluster; web services secured with X.509 and SAML.

**Senior Architect** — Sierra Systems Group · 2007 — Access management, directory schema design, and web
SSO federation.

**Principal Consultant** — Oracle Corporation · Toronto · 2006 – 2007 — Highly available identity and
access management with portal single sign-on; certificate authority for automated X.509 provisioning.

---

## CERTIFICATIONS

**Certificate of Cloud Security Knowledge (CCSK)** — Cloud Security Alliance

## EDUCATION

[Degree, institution — please fill in]

---
---

# LinkedIn text (paste-ready)

## Headline (keep SAP keywords — recruiters search on them)

```text
Identity & Access Security Architect | SAP Security, IAM & Federation (IAS/IAG/BTP, SAML/OIDC, Okta,
Entra, SailPoint, CyberArk) | Identity and policy for AI systems | Available for contract
```

## About section

```text
I build the layer that decides what an identity is allowed to reach.

For twenty years that has meant single sign-on and federation, identity
governance, privileged access, and the formal security assessments that
get systems authorized to operate — across federal departments and large
regulated enterprises. SAML 2.0, OAuth 2.0 and OIDC on ForgeRock, Okta,
Keycloak, PingIdentity, ADFS, Entra ID and Oracle. Identity governance
with SailPoint, privileged access with CyberArk. On the SAP side: IAS as
a SAML identity provider proxy, IAG governance, Identity Provisioning
Service, SAP SSO, Enterprise Threat Detection, and BTP application
deployment and service configuration. Alongside that, security assessment
and authorization under ITSG-33, ITSP-50, NIST and FedRAMP.

I am an architect who implements. Python, Java, React, Docker — the
designs I produce are ones I can build.

Lately I have been applying the same specialization to AI systems, where
the identity question is newly unsolved. Directory groups do not map onto
vector database metadata, so internal AI assistants stall in security
review. Agents can call SIEM tools that block an IP or isolate a host,
and nobody can say which caller is permitted to trigger which action. I
have built and open-sourced two controls for this: Marifort Gate, a
gateway that enforces identity-based document authorization before
retrieval, and SOC Governance, which adds the missing layer: policy
on who may call which tool with which arguments, a human gate before
any write, and an audit trail that outlives the call. The model
synthesizes; it does not execute. One decides what an AI may read;
the other what it may do.

Available for contract engagements — Canada or North America remote,
through my company. Interested in SAP security and identity work,
enterprise IAM programmes, and identity and governance for AI systems.
```

## Skills to add (LinkedIn matches on these)

```text
Identity & Access Management (IAM) · SAML · OAuth 2.0 · OpenID Connect · Single Sign-On · Okta ·
Microsoft Entra ID · ForgeRock · Keycloak · PingIdentity · ADFS · SailPoint · CyberArk · PKI ·
Zero Trust · SAP Security · SAP BTP · SAP IAS · SAP IAG · SAP Single Sign-On · SAP Enterprise Threat
Detection · S/4HANA · Security Architecture · ITSG-33 · NIST · FedRAMP · Threat and Risk Assessment ·
Azure Sentinel · SIEM · Elasticsearch · Python · FastAPI · Java · Spring Boot · React · Docker ·
Kubernetes / Helm · AI Security · LLM Security · Model Context Protocol (MCP) · RAG
```
