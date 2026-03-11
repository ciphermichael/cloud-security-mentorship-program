# 📅 Week 2 — S3 Security & Encryption

**Phase 1: Foundations | Project: 02-storage-security-scanner**

---

## 🎯 Learning Objectives

- Identify S3 public access misconfigurations (ACLs, bucket policies, Block Public Access)
- Detect unencrypted S3 buckets and objects
- Use regex to find PII patterns in object samples
- Understand AWS Macie as a managed PII scanner

---

## 📅 Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | S3 security model — ACLs, bucket policies, Block Public Access settings | 2 hrs |
| Tue | S3 encryption — SSE-S3, SSE-KMS, SSE-C, client-side | 2 hrs |
| Wed | AWS Macie overview and Python API | 2 hrs |
| Thu | Build the bucket scanner — public access + encryption checks | 2 hrs |
| Fri | Add PII detection using regex (email, phone, SSN, credit card) | 2 hrs |
| Sat | Test, generate sample findings report, push to GitHub | 3 hrs |
| Sun | Review + Week 3 reading | 1 hr |

---

## 📚 Study Resources

- [S3 Security Best Practices — AWS Docs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [OWASP Cloud Security Testing Guide](https://owasp.org/www-project-cloud-security-testing-guide/)

---

## 📝 Weekly Assignment

### Task: S3 Security & PII Scanner

Build a scanner that:

1. **Lists all S3 buckets** in the account
2. **Checks each bucket** for:
   - Public ACL (`public-read`, `public-read-write`)
   - Missing "Block Public Access" settings
   - No default encryption policy
   - Versioning disabled
   - MFA delete disabled
   - No server access logging
3. **Samples 5 random objects** from each bucket and scans content for:
   - Email addresses (`[\w.]+@[\w.]+\.\w+`)
   - US SSNs (`\d{3}-\d{2}-\d{4}`)
   - Credit card numbers (Luhn check)
4. **Generates HTML report** with risk summary

### Acceptance Criteria

- [ ] Runs with `python scanner.py --profile default`
- [ ] HTML report shows bucket risk levels
- [ ] PII findings masked in output (e.g. `***-**-1234`)
- [ ] At least 6 security checks implemented
- [ ] README with screenshots of sample output

---

## ✅ Submission Checklist

- [ ] GitHub repo updated with Week 2 work
- [ ] HTML report sample in `reports/`
- [ ] Reflection: what PII patterns could be added?

---

## 🔗 Links to Project

→ Full project: [`projects/02-storage-security-scanner/`](../../projects/02-storage-security-scanner/)  
→ Step-by-step guide: [`projects/02-storage-security-scanner/STEPS.md`](../../projects/02-storage-security-scanner/STEPS.md)
