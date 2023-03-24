package com.example.app.model.request;

import com.example.app.model.constant.Country;
import com.fasterxml.jackson.annotation.JsonProperty;
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
public class CityRequestModel implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @JsonProperty("city")
    private String city;

    @JsonProperty("countryId")
    private Country countryId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CityRequestModel that = (CityRequestModel) o;
        return Objects.equal(city, that.city)
                && countryId == that.countryId;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(city, countryId);
    }
}
