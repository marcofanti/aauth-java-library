package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StructuredFieldsTest {

    @Test
    void parsesTypedDictionaryMembersInOrder() {
        Map<String, StructuredFields.Item> members = StructuredFields.parseDictionary(
                "requirement=auth-token; resource-token=\"a.b.c\", n=-12, d=1.5, flag, b=?0, bytes=:AAEC:");

        assertThat(members.keySet()).containsExactly("requirement", "n", "d", "flag", "b", "bytes");
        StructuredFields.Item requirement = members.get("requirement");
        assertThat(requirement.value()).isEqualTo(new StructuredFields.Token("auth-token"));
        assertThat(requirement.params()).containsEntry("resource-token", "a.b.c");
        assertThat(members.get("n").value()).isEqualTo(-12L);
        assertThat(members.get("d").value()).isEqualTo(new BigDecimal("1.5"));
        assertThat(members.get("flag").value()).isEqualTo(true);
        assertThat(members.get("b").value()).isEqualTo(false);
        assertThat(members.get("bytes").value()).isEqualTo(new StructuredFields.ByteSequence("AAEC"));
    }

    @Test
    void parsesInnerListsWithParameters() {
        StructuredFields.Item sig = StructuredFields.parseDictionary("sig=(\"@method\" tok;x=1);created=5")
                .get("sig");

        assertThat(sig.value())
                .isEqualTo(List.of(
                        new StructuredFields.Item("@method", Map.of()),
                        new StructuredFields.Item(new StructuredFields.Token("tok"), Map.of("x", 1L))));
        assertThat(sig.params()).containsEntry("created", 5L);
    }

    @Test
    void plainUnwrapsTokens() {
        assertThat(StructuredFields.plain(new StructuredFields.Token("jkt"))).isEqualTo("jkt");
        assertThat(StructuredFields.plain(7L)).isEqualTo(7L);
    }

    @Test
    void rejectsInvalidDictionaries() {
        for (String invalid : List.of(
                "Key=1",
                "a=1,",
                "a=1 b=2",
                "a=\"open",
                "a=\"bad\\q\"",
                "a=-",
                "a=1.",
                "a=1234567890123456",
                "a=?2",
                "a=:abc",
                "a=(1 2",
                "a=(1,2)",
                "a=@",
                "a=")) {
            assertThatThrownBy(() -> StructuredFields.parseDictionary(invalid))
                    .as(invalid)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
