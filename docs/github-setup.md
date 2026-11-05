# Connecting GitHub — how we work together

## The honest setup

I can **write, edit, and run code** in our shared workspace (`/home/user/filetrail`).
What I **cannot** do is log into your GitHub account. I have no GitHub connector in this
conversation, and I don't store your credentials.

So the split of duties is:

- **Me:** write code, run it, test it, commit it locally with clear messages.
- **You:** run one `git push` when a milestone is ready — or set it up so I can push once.

There are three ways to do this. Pick one and we'll go.

---

## Option A — You create the repo, I do everything else (recommended)

Fastest to get moving. Takes about 2 minutes.

1. On GitHub: **New repository** → name it `filetrail` → **Private** → do **not** add a
   README/gitignore (we already have files) → Create.
2. Send me the repo URL (e.g. `https://github.com/yourname/filetrail`).
3. I'll wire the remote, commit everything, and hand you a single command to run:

```bash
cd /home/user/filetrail && git push -u origin main
```

GitHub will ask for credentials on your side — that's the one step that must stay with you.

From then on, every milestone I finish, I commit locally and hand you one `git push`.

---

## Option B — Give me push access via a token (fully hands-off)

If you want me to push without you touching a terminal:

1. Create a **fine-grained personal access token** on GitHub:
   Settings → Developer settings → Personal access tokens → Fine-grained tokens →
   Generate new token.
   - Repository access: **Only select repositories** → `filetrail`
   - Permissions: **Contents: Read and write** (nothing else)
   - Expiry: short — 7 or 30 days
2. Send it to me, and I'll configure the remote so pushes work.

⚠️ **Safety notes, read these:**

- Use a **fine-grained token scoped to this one repo**, never a classic token with full
  account access.
- Give it the **shortest expiry** you can.
- Keep the repo **private**.
- Revoke it on GitHub the moment we're done or if anything looks off.
- Anything you paste into this chat is visible to the conversation — so treat the token
  as semi-exposed, and rotate it when the project ships.

Honestly: Option A gives you 95% of the benefit with none of this risk. I'd only reach
for Option B if you want me pushing several times a day.

---

## Option C — You work on your machine, I plan

You clone the repo locally, and I act as architect/reviewer: you paste code or file
contents, I review, refactor, and tell you what to commit. Slower loop, but you keep
100% of the keys and you learn the codebase deeply.

Good if you want to be able to defend every line in a viva — or to a future employer.

---

## Branch convention (once we're live)

- `main` — always working, always deployable
- `feat/<name>` — one feature at a time
- Commit messages: `feat: check-in flow`, `fix: aging query off-by-one`, `docs: pilot one-pager`

## What goes in the repo

```
filetrail/
├── README.md          # the plan, the scope, the decisions
├── docs/              # recon notes, flow maps, pitch, decisions
├── app/               # the actual product (added in Phase 3)
└── .gitignore
```

We commit the **thinking** too, not just the code. When a registrar asks "why did you
build it this way?", the answer is in the repo with a date on it.
