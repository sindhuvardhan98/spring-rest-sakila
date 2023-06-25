package com.example.app.app.rental.controller;

import com.example.app.app.rental.assembler.RentalRepresentationModelAssembler;
import com.example.app.app.rental.domain.dto.RentalDto;
import com.example.app.app.rental.service.RentalService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.hateoas.CollectionModel;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@RestController
@RequestMapping(value = "/rentals")
@RequiredArgsConstructor
public class RentalController {
    private final RentalService rentalService;
    private final RentalRepresentationModelAssembler rentalAssembler;

    @GetMapping(path = "")
    public ResponseEntity<CollectionModel<RentalDto.RentalResponse>> getRentalList(
            @PageableDefault(size = 10, page = 0, direction = Sort.Direction.ASC) Pageable pageable) {
        return ResponseEntity.ok(rentalAssembler.toCollectionModel(
                rentalService.getRentalList(pageable)));
    }

    @PostMapping(path = "")
    public ResponseEntity<Void> rentDvd(@RequestBody RentalDto.RentalCreateRequest model) {
        if (model.getRentalDate() == null) {
            model.setRentalDate(LocalDateTime.now());
        }
        var result = rentalService.rentDvd(model);
        return ResponseEntity.created(linkTo(methodOn(RentalController.class)
                .getRental(result.getRentalId())).toUri()).build();
    }

    @GetMapping(path = "/{rentalId}")
    public ResponseEntity<RentalDto.RentalResponse> getRental(@PathVariable Integer rentalId) {
        return rentalService.getRental(rentalId)
                .map(rentalAssembler::toModel)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping(path = "/{rentalId}")
    public ResponseEntity<Void> updateRental(@PathVariable Integer rentalId,
                                             @ModelAttribute RentalDto.RentalUpdateRequest model) {
        var result = rentalService.updateRental(rentalId, model);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping(path = "/{rentalId}")
    public ResponseEntity<Void> deleteRental(@PathVariable Integer rentalId) {
        rentalService.deleteRental(rentalId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping(path = "/return")
    public ResponseEntity<Void> returnDvd(@RequestBody Map<String, String> input) {
        if (input.get("returnDate") == null) {
            input.put("returnDate", LocalDateTime.now().toString());
        }
        var result = rentalService.returnDvd(input);
        return ResponseEntity.ok().build();
    }
}
