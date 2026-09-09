# Lab: SQL Injection — Filter Bypass
https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

## Summary
SQL injection vulnerability in a WHERE clause allowing retrieval of hidden data. The application directly concatenates the `category` parameter into a SQL query string without parameterized queries or input sanitization, allowing arbitrary SQL syntax to execute as part of the original query.

## Steps to Reproduce
1. Sent the original request to `/filter?category=Gifts`
2. Observed the response only returned Gifts-category products
3. Modified the `category` parameter to `Gifts' OR 1=1--` in Burp Repeater
4. Sent the modified request and observed all products returned, confirming the filter was bypassed

## Evidence

**Original request:**
![Original request showing category=Gifts filter](images/sqli-lab1-original-payload-request.png)

**Original response (filtered correctly):**
![Original response showing filtered Gifts category only](images/sqli-lab1-original-payload-response.png)

**Payload request:**
![Payload request with category=Gifts' OR 1=1--](images/sqli-lab1-payload-request.png)

**Bypassed response (all products returned):**
![Bypassed response showing all products returned](images/sqli-lab1-payload-response.png)

## Injection Point
The injection point was the `category` parameter in `/filter?category=Gifts`. I identified it by reasoning about server-side behavior:

```python
query = f"SELECT * FROM products WHERE category = '{category}' AND released = 1"
```

- `category` is a string filter concatenated directly: `WHERE category = '` + category + `'`
- `productId` is an integer primary key likely using parameterized queries or integer validation
- String concatenation on user-controlled input = injection vulnerability; validated integers are typically safe

## Payload
`category=Gifts' OR 1=1--`

- `'` — closes the opening quote around `'Gifts'` in the original query, giving control over what comes next
- `OR 1=1` — a condition that's always true, so the entire WHERE clause evaluates true for every row, bypassing the category filter
- `--` — SQL comment delimiter; everything after it is ignored, canceling the trailing `AND released = 1`

## Impact
This vulnerability allowed an unauthenticated attacker to bypass the application's intended category filter and retrieve the full product catalog, including unreleased/hidden products that should not have been visible (rows where `released = 1` was not satisfied). No authentication was required to exploit this — the attacker needed only to modify a single query parameter.

While this specific lab is limited to a product listing endpoint with no sensitive user data in scope, the underlying flaw — unsanitized string concatenation into a SQL query — is not limited to this context. The same pattern, if present in a query touching authentication, session, or user records elsewhere in an application, could extend to credential exposure or authentication bypass. That broader consequence is not demonstrated here; it is a reasonable extrapolation based on the root cause, not a claim about this lab's actual scope.

## Remediation
Use parameterized queries (prepared statements) instead of string concatenation.

**Vulnerable (string concatenation):**
```python
query = f"SELECT * FROM products WHERE category = '{category}' AND released = 1"
```

**Fixed (parameterized):**
```python
query = "SELECT * FROM products WHERE category = ? AND released = 1"
cursor.execute(query, (category,))
```

**Additional defenses:**
- Input validation — ensure `category` matches an expected pattern (e.g. `[a-zA-Z]+`)
- Whitelist allowed values — only accept categories from a predefined list
- Never trust user input — treat all parameters as dangerous until validated
- Use ORM frameworks — they parameterize queries by default

## Severity
High — unauthenticated data exposure via direct query manipulation.
