# Guía práctica (8 niveles)

1. ¿Qué hace EmailFallback en un IdP OIDC?
2. `p01`: email_verified=false → LINKED pre, NEW post.
3. Localiza en el diff la línea `emailFallbackAllowed := ...`.
4. `n01`: verified=true enlaza en ambos.
5. `boolish`: ¿por qué "1" cuenta como true?
6. `n03`: sin EmailFallback ni UsernameFallback, el caller no busca.
7. Diseña un caso UsernameFallback + email no verificado.
8. Relaciónalo con account takeover en un laboratorio HTB propio (local).

Más allá: regenera expected.tsv y comprueba el oráculo.
