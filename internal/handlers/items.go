package handlers

import (
	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/services"
	"gofiber_template/internal/validator"
)

// ItemsHandler holds DB for item handlers.
type ItemsHandler struct {
	Service *services.ItemsService
}

const defaultPageSize = 20
const maxPageSize = 100

// List returns items with pagination.
func (h *ItemsHandler) List(c *fiber.Ctx) error {
	page, limit, err := validator.ParsePagination(c.Query("page"), c.Query("limit"), defaultPageSize, maxPageSize)
	if err != nil {
		return err
	}

	result, err := h.Service.List(page, limit)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"data": result.Items,
		"meta": fiber.Map{
			"page":       result.Page,
			"limit":      result.Limit,
			"total":      result.Total,
			"total_page": result.TotalPages,
		},
	})
}

// Get returns a single item by ID.
func (h *ItemsHandler) Get(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	item, err := h.Service.Get(id)
	if err != nil {
		if err == services.ErrItemNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(item)
}

// CreateRequest is the JSON body for creating an item.
type CreateRequest struct {
	Name string `json:"name"`
}

// Create creates a new item.
func (h *ItemsHandler) Create(c *fiber.Ctx) error {
	var req CreateRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	errs := &validator.Errors{}
	validator.ValidateRequiredString(errs, "name", req.Name)
	if errs.HasAny() {
		return errs
	}
	item, err := h.Service.Create(req.Name)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(item)
}

// UpdateRequest is the JSON body for updating an item.
type UpdateRequest struct {
	Name string `json:"name"`
}

// Update updates an item by ID.
func (h *ItemsHandler) Update(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	var req UpdateRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	errs := &validator.Errors{}
	validator.ValidateRequiredString(errs, "name", req.Name)
	if errs.HasAny() {
		return errs
	}
	item, err := h.Service.Update(id, req.Name)
	if err != nil {
		if err == services.ErrItemNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(item)
}

// Delete soft-deletes an item by ID.
func (h *ItemsHandler) Delete(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	if err := h.Service.Delete(id); err != nil {
		if err == services.ErrItemNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(fiber.Map{"message": "deleted"})
}
