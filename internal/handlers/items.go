package handlers

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"gofiber_template/internal/models"
	"gofiber_template/internal/validator"
)

// ItemsHandler holds DB for item handlers.
type ItemsHandler struct {
	DB *gorm.DB
}

const defaultPageSize = 20
const maxPageSize = 100

// List returns items with pagination.
func (h *ItemsHandler) List(c *fiber.Ctx) error {
	page, limit, err := validator.ParsePagination(c.Query("page"), c.Query("limit"), defaultPageSize, maxPageSize)
	if err != nil {
		return err
	}
	offset := (page - 1) * limit

	var items []models.Item
	var total int64
	if err := h.DB.Model(&models.Item{}).Count(&total).Error; err != nil {
		return err
	}
	if err := h.DB.Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"data": items,
		"meta": fiber.Map{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"total_page": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

// Get returns a single item by ID.
func (h *ItemsHandler) Get(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	var item models.Item
	if err := h.DB.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
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
	item := models.Item{Name: req.Name}
	if err := h.DB.Create(&item).Error; err != nil {
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
	var item models.Item
	if err := h.DB.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	item.Name = req.Name
	if err := h.DB.Save(&item).Error; err != nil {
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
	result := h.DB.Delete(&models.Item{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fiber.NewError(fiber.StatusNotFound, "not found")
	}
	return c.JSON(fiber.Map{"message": "deleted"})
}
