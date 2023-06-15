package com.example.app.app.catalog.domain.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldNameConstants;

@Getter
@Setter
@ToString
@FieldNameConstants
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FilmTextModel {
    @JsonProperty("filmId")
    private Integer filmId;

    @JsonProperty("title")
    @Size(min = 1, max = 255)
    private String title;

    @JsonProperty("description")
    @Size(max = 65535)
    private String description;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FilmTextModel that = (FilmTextModel) o;
        return Objects.equal(filmId, that.filmId)
                && Objects.equal(title, that.title)
                && Objects.equal(description, that.description);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(filmId, title, description);
    }
}