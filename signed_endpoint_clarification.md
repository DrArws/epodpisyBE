Ano, `/signed` endpoint **by měl být také obsluhován Supabase Edge Function proxy**.

Důvody jsou následující:

1.  **Konzistence rozhraní**: Pokud `POST /v1/signing/sessions/{token}/complete` prochází přes proxy (což je náš nový design), je logické, aby i `GET /v1/signing/sessions/{token}/signed` (který frontend používá k dotazování na stav podpisu) procházel stejnou cestou. Zajišťuje to jednotné a konzistentní API pro frontend.
2.  **Odlehčení Cloud Runu**: Původní motivací bylo odlehčit Cloud Run od přímých interakcí s PostgreSQL (kvůli problémům s `.single()` a RLS). Přesunutí i `GET` dotazů na stav do Edge Function proxy dále snižuje zátěž Cloud Runu a využívá síly Edge Functions pro rychlé a bezpečné dotazy na databázi.
3.  **Centralizace logiky veřejného přístupu**: Edge Function proxy je navržena jako zabezpečená brána pro neautentizované uživatele. Zpracování jak odeslání podpisu, tak dotazování na jeho stav na jednom místě zjednodušuje správu a zabezpečení této veřejné interakce.

Tím pádem, Edge Function `public-signing-proxy` bude obsluhovat jak:
*   `GET /v1/signing/sessions/:token` (pro metadata session před podpisem)
*   `POST /v1/signing/sessions/:token/complete` (pro odeslání podpisu a spuštění asynchronního procesu)
*   `GET /v1/signing/sessions/:token/signed` (pro dotazování na stav podpisu po odeslání)
