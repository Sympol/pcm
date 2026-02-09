# Dependency Monitoring and Updates

This document describes the tools and processes put in place to monitor the dependencies of the PCM project and ensure they remain secure and up to date.

## 1. Local Tools (Maven)

We have configured two essential Maven plugins in the root `pom.xml` to allow you to check the status of your dependencies locally.

### Checking for new versions

The `versions-maven-plugin` has been added. It allows you to see which libraries have newer versions available.

**Command:**

```bash
mvn versions:display-dependency-updates
```

*Note: This will check all modules of the project.*

### Checking vulnerabilities (CVE)

The `dependency-check-maven` (OWASP) plugin has been added. It scans your dependencies for known vulnerabilities (CVEs).

**Command:**

```bash
mvn org.owasp:dependency-check-maven:check
```

*Note: The report will be generated in `target/dependency-check-report.html`. Open this file in your browser to see the details.*

> [!TIP]
> **NVD API Key**: The first run allows downloading the vulnerability database, which can fail (403/404) due to NVD rate limits.
> It is highly recommended to obtain an [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) and configure it in your `settings.xml` or via command line:
> `mvn org.owasp:dependency-check-maven:check -DnvdApiKey=YOUR_KEY`

---

## 2. Automation (CI/CD)

For continuous monitoring without manual intervention, we recommend using tools connected to your code repository (GitHub/GitLab).

### GitHub Dependabot (Recommended)

If your code is hosted on GitHub, Dependabot is the simplest solution. It automatically creates Pull Requests to update vulnerable or outdated dependencies.

**Configuration:**
Create a `.github/dependabot.yml` file at the root of the project:

```yaml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      spring-boot:
        patterns:
          - "org.springframework.boot:*"
          - "org.springframework.cloud:*"
```

### Renovate Bot

[Renovate](https://docs.renovatebot.com/) is a more configurable alternative to Dependabot, capable of grouping updates (“Grouped Updates”) to avoid Pull Request “noise”.

---

## 3. Best Practices

1. **Regular updates**: Run the `mvn versions:display-dependency-updates` command at the beginning of each sprint.
2. **Security overrides**: If a critical vulnerability is discovered in a transitive dependency (e.g., `netty`), use the `<dependencyManagement>` section of the root `pom.xml` to force a secure version (as we did for the recent remediation).
3. **Automated tests**: Never merge a dependency update unless the test suite (`mvn test`) passes successfully.
