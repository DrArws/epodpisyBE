Dobrý den týme frontendu,

provedli jsme významnou změnu v architektuře zpracování podpisu, která zvyšuje spolehlivost a rychlost odezvy pro uživatele. Zde je přehled, jak by frontend měl interagovat s novým podpisovým flow, zejména pro akci dokončení podpisu:

---

### Nový asynchronní proces dokončení podpisu

**1. Odeslání podpisu (Endpoint `POST /v1/signing/sessions/{token}/complete`):**

*   **Vaše akce**: Frontend stále volá tento endpoint s daty podpisu (např. `signature_image_base64`, `field_id`, `consent_accepted`).
*   **Nová odezva**: Místo čekání na kompletní podepsání PDF (které nyní probíhá asynchronně na backendu), tento endpoint **ihned vrátí status `202 Accepted`** s tělem odpovědi `{ "status": "processing" }`.
    *   Tato odpověď znamená, že váš požadavek byl úspěšně přijat a backend začal s asynchronním zpracováním podpisu.
*   **Idempotence**: Funkce zůstává idempotentní. Pokud je požadavek odeslán vícekrát se stejným `Idempotency-Key` (nebo pokud je podpis již dokončen), systém vrátí příslušnou status `409 Conflict` s informací o tom, zda se dokument již podepisuje, nebo je již podepsán (a případně i s `signed_pdf_url` z cache).

**2. Dotazování na stav dokončení (Endpoint `GET /v1/signing/sessions/{token}/signed`):**

*   **Vaše akce**: Po obdržení `202 Accepted` z endpointu `/complete` by frontend měl **začít pravidelně dotazovat** nový endpoint `GET /v1/signing/sessions/{token}/signed`.
*   **Očekávané odpovědi**:
    *   **`200 OK` s `{ "status": "processing" }`**: Dokument se stále zpracovává. Frontend by měl pokračovat v dotazování (např. s exponenciálním zpožděním).
    *   **`200 OK` s `{ "status": "signed", "signed_document_url": "https://...", "signed_at": "YYYY-MM-DDTHH:MM:SSZ", "verification_id": "VRF-XXXXXX" }`**: Dokument byl úspěšně podepsán a je připraven ke stažení/zobrazení.
        *   `signed_document_url` je časově omezená URL pro stažení finálního podepsaného PDF.
        *   `signed_at` je čas dokončení podpisu.
        *   `verification_id` je unikátní identifikátor podpisu pro ověření.
*   **Strategie dotazování**: Doporučujeme implementovat strategii exponenciálního backoffu pro dotazování (např. 2s, 4s, 8s, 16s, atd., s maximálním počtem pokusů nebo časovým limitem), aby se předešlo zbytečnému zatížení serveru.

**3. Zobrazení/Stažení podepsaného dokumentu:**

*   Jakmile frontend obdrží `signed_document_url`, může ji použít k zobrazení dokumentu v prohlížeči (např. v iframe) nebo k nabídnutí odkazu ke stažení uživateli.

### Zpracování chyb

*   **Okamžité chyby z `/complete`**: Chyby jako `OTP_NOT_VERIFIED`, `SIGN_LINK_EXPIRED`, `VALIDATION_ERROR` nebo jiné systémové chyby (`500 SERVER_ERROR`) budou stále vráceny z endpointu `/complete` s příslušným HTTP status kódem a standardizovaným JSON tělem `{ "code": "...", "message": "..." }`. Frontend by měl tyto chyby zpracovat jako dosud.
*   **Chyby během dotazování na `/signed`**: Stejně tak endpoint `/signed` může vrátit chyby pro neplatné tokeny, nebo pokud session mezitím vypršela apod.

---

Tento asynchronní přístup zlepšuje uživatelský prožitek tím, že uživatel okamžitě vidí, že jeho požadavek byl přijat, a zároveň zvyšuje odolnost celého systému proti timeoutům a neočekávaným chybám.

V případě jakýchkoliv dotazů nebo nejasností se prosím obraťte na backend tým.
