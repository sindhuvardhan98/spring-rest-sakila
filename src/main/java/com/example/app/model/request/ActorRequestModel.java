package com.example.app.model.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.google.common.base.Objects;
import lombok.*;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActorRequestModel implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @JsonProperty("firstName")
    @JacksonXmlProperty(localName = "firstName")
    private String firstName;

    @JsonProperty("lastName")
    @JacksonXmlProperty(localName = "lastName")
    private String lastName;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ActorRequestModel that = (ActorRequestModel) o;
        return Objects.equal(firstName, that.firstName)
                && Objects.equal(lastName, that.lastName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(firstName, lastName);
    }
}
