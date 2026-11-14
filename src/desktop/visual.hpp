#pragma once
#include "icons.hpp"
#include <algorithm>
#include <array>
#include <d2d1.h>
#include <dwrite.h>
#include <map>
#include <string_view>
#include <wrl/client.h>

namespace scau::desktop::visual {
using Microsoft::WRL::ComPtr;
inline constexpr COLORREF Paper = RGB(252, 253, 251), White = RGB(255, 255, 255), Ink = RGB(32, 43, 39),
                          Muted = RGB(122, 132, 126), Subtle = RGB(155, 165, 155), Pine = RGB(36, 116, 92),
                          Deep = RGB(25, 95, 73), Soft = RGB(237, 245, 239), Sidebar = RGB(245, 247, 243),
                          Line = RGB(230, 234, 229), Border = RGB(211, 221, 209), Warn = RGB(161, 119, 41),
                          Error = RGB(173, 91, 73);
inline COLORREF mix(COLORREF a, COLORREF b, double t) {
    t = std::clamp(t, 0., 1.);
    return RGB(int(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * t),
               int(GetGValue(a) + (GetGValue(b) - GetGValue(a)) * t),
               int(GetBValue(a) + (GetBValue(b) - GetBValue(a)) * t));
}
inline D2D1_COLOR_F rgba(COLORREF c, float alpha = 1.f) {
    return D2D1::ColorF(GetRValue(c) / 255.f, GetGValue(c) / 255.f, GetBValue(c) / 255.f, alpha);
}
struct Rect {
    float x, y, w, h;
    D2D1_RECT_F d2d() const { return D2D1::RectF(x, y, x + w, y + h); }
    Rect inset(float a) const { return {x + a, y + a, w - 2 * a, h - 2 * a}; }
};
enum Type { Text, SmallText, MediumText, HeadingText, StatusText, BrandText, MonoText, TypeCount };

// One reusable DC target and cached text formats/paths for all HWND controls.
// DWM supplies the top-level shadow; no bitmap cache or idle redraw loop is used.
class Renderer {
    ComPtr<ID2D1Factory> factory_;
    ComPtr<IDWriteFactory> write_;
    ComPtr<ID2D1DCRenderTarget> target_;
    ComPtr<ID2D1SolidColorBrush> brush_;
    ComPtr<ID2D1StrokeStyle> stroke_;
    std::array<ComPtr<IDWriteTextFormat>, TypeCount> formats_;
    std::map<Icon, ComPtr<ID2D1PathGeometry>> icons_;
    std::map<std::pair<COLORREF, COLORREF>, ComPtr<ID2D1LinearGradientBrush>> gradients_;

  public:
    bool begin(HDC dc, RECT bounds, UINT dpi, COLORREF background) {
        if (!factory_)
            D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, factory_.GetAddressOf());
        if (!write_)
            DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                reinterpret_cast<IUnknown **>(write_.GetAddressOf()));
        if (!factory_ || !write_)
            return false;
        if (!target_) {
            auto props = D2D1::RenderTargetProperties();
            props.pixelFormat = D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE);
            if (FAILED(factory_->CreateDCRenderTarget(&props, target_.GetAddressOf())))
                return false;
            target_->CreateSolidColorBrush(rgba(Ink), brush_.ReleaseAndGetAddressOf());
        }
        if (!brush_ || FAILED(target_->BindDC(dc, &bounds)))
            return false;
        target_->SetDpi(float(dpi), float(dpi));
        target_->SetTransform(D2D1::Matrix3x2F::Identity());
        target_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);
        target_->BeginDraw();
        target_->Clear(rgba(background));
        return true;
    }
    void end() {
        if (target_ && target_->EndDraw() == D2DERR_RECREATE_TARGET)
            reset();
    }
    void reset() {
        gradients_.clear();
        brush_.Reset();
        target_.Reset();
    }
    void fill(Rect r, COLORREF c, float radius = 0, float alpha = 1) {
        brush_->SetColor(rgba(c, alpha));
        if (radius)
            target_->FillRoundedRectangle(D2D1::RoundedRect(r.d2d(), radius, radius), brush_.Get());
        else
            target_->FillRectangle(r.d2d(), brush_.Get());
    }
    void outline(Rect r, COLORREF c, float radius = 0, float width = 1) {
        brush_->SetColor(rgba(c));
        if (radius)
            target_->DrawRoundedRectangle(D2D1::RoundedRect(r.d2d(), radius, radius), brush_.Get(), width);
        else
            target_->DrawRectangle(r.d2d(), brush_.Get(), width);
    }
    void gradient(Rect r, COLORREF a, COLORREF b, float radius) {
        auto &gradient = gradients_[{a, b}];
        if (!gradient) {
            D2D1_GRADIENT_STOP stops[] = {{0, rgba(a)}, {1, rgba(b)}};
            ComPtr<ID2D1GradientStopCollection> collection;
            if (SUCCEEDED(target_->CreateGradientStopCollection(stops, 2, collection.GetAddressOf())))
                target_->CreateLinearGradientBrush(
                    D2D1::LinearGradientBrushProperties(D2D1::Point2F(r.x, r.y),
                                                        D2D1::Point2F(r.x + r.w, r.y + r.h)),
                    collection.Get(), gradient.GetAddressOf());
        }
        if (gradient) {
            gradient->SetStartPoint(D2D1::Point2F(r.x, r.y));
            gradient->SetEndPoint(D2D1::Point2F(r.x + r.w, r.y + r.h));
            target_->FillRoundedRectangle(D2D1::RoundedRect(r.d2d(), radius, radius), gradient.Get());
        } else
            fill(r, a, radius);
    }
    void line(float x, float y, float x2, float y2, COLORREF c, float width = 1) {
        brush_->SetColor(rgba(c));
        target_->DrawLine(D2D1::Point2F(x, y), D2D1::Point2F(x2, y2), brush_.Get(), width);
    }
    void dot(float x, float y, float radius, COLORREF c) {
        brush_->SetColor(rgba(c));
        target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(x, y), radius, radius), brush_.Get());
    }
    void ring(float x, float y, float radius, COLORREF c, float width = 1) {
        brush_->SetColor(rgba(c));
        target_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(x, y), radius, radius), brush_.Get(), width);
    }
    IDWriteTextFormat *format(Type type) {
        if (!formats_[type]) {
            constexpr float sizes[] = {13, 11.5f, 15, 24, 30, 13, 12};
            constexpr DWRITE_FONT_WEIGHT weights[] = {
                DWRITE_FONT_WEIGHT_NORMAL,    DWRITE_FONT_WEIGHT_NORMAL,    DWRITE_FONT_WEIGHT_SEMI_BOLD,
                DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_WEIGHT_SEMI_BOLD,
                DWRITE_FONT_WEIGHT_NORMAL};
            write_->CreateTextFormat(type == MonoText ? L"Consolas" : L"Segoe UI", nullptr, weights[type],
                                     DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, sizes[type],
                                     L"zh-CN", formats_[type].GetAddressOf());
            if (formats_[type]) {
                formats_[type]->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
                formats_[type]->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            }
        }
        return formats_[type].Get();
    }
    float measure(std::wstring_view value, Type type = Text) {
        ComPtr<IDWriteTextLayout> layout;
        if (!format(type) || FAILED(write_->CreateTextLayout(value.data(), UINT32(value.size()), format(type),
                                                             1600, 200, layout.GetAddressOf())))
            return 0;
        DWRITE_TEXT_METRICS metrics{};
        layout->GetMetrics(&metrics);
        return metrics.width;
    }
    void text(std::wstring_view value, Rect rect, COLORREF c, Type type = Text,
              DWRITE_TEXT_ALIGNMENT alignment = DWRITE_TEXT_ALIGNMENT_LEADING, bool wrap = false) {
        auto *f = format(type);
        if (!f || value.empty())
            return;
        f->SetTextAlignment(alignment);
        f->SetWordWrapping(wrap ? DWRITE_WORD_WRAPPING_WRAP : DWRITE_WORD_WRAPPING_NO_WRAP);
        brush_->SetColor(rgba(c));
        target_->DrawTextW(value.data(), UINT32(value.size()), f, rect.d2d(), brush_.Get(),
                           D2D1_DRAW_TEXT_OPTIONS_CLIP);
    }
    void icon(Icon which, Rect rect, COLORREF c, float weight = 1.65f, float rotation = 0) {
        if (which == Icon::None)
            return;
        auto &path = icons_[which];
        if (!path) {
            factory_->CreatePathGeometry(path.GetAddressOf());
            if (!path)
                return;
            ComPtr<ID2D1GeometrySink> sink;
            if (FAILED(path->Open(sink.GetAddressOf()))) {
                path.Reset();
                return;
            }
            bool open = false;
            for (const auto &p : icon_path(which)) {
                switch (p.type) {
                case 'M':
                    if (open)
                        sink->EndFigure(D2D1_FIGURE_END_OPEN);
                    sink->BeginFigure(D2D1::Point2F(p.x1, p.y1), D2D1_FIGURE_BEGIN_HOLLOW);
                    open = true;
                    break;
                case 'L':
                    sink->AddLine(D2D1::Point2F(p.x1, p.y1));
                    break;
                case 'C':
                    sink->AddBezier(D2D1::BezierSegment(D2D1::Point2F(p.x1, p.y1), D2D1::Point2F(p.x2, p.y2),
                                                        D2D1::Point2F(p.x3, p.y3)));
                    break;
                case 'Q':
                    sink->AddQuadraticBezier(
                        D2D1::QuadraticBezierSegment(D2D1::Point2F(p.x1, p.y1), D2D1::Point2F(p.x2, p.y2)));
                    break;
                case 'Z':
                case 'E':
                    if (open)
                        sink->EndFigure(p.type == 'Z' ? D2D1_FIGURE_END_CLOSED : D2D1_FIGURE_END_OPEN);
                    open = false;
                    break;
                }
            }
            if (open)
                sink->EndFigure(D2D1_FIGURE_END_OPEN);
            if (FAILED(sink->Close())) {
                path.Reset();
                return;
            }
        }
        if (!stroke_) {
            auto props = D2D1::StrokeStyleProperties();
            props.startCap = props.endCap = props.dashCap = D2D1_CAP_STYLE_ROUND;
            props.lineJoin = D2D1_LINE_JOIN_ROUND;
            factory_->CreateStrokeStyle(props, nullptr, 0, stroke_.GetAddressOf());
        }
        target_->SetTransform(D2D1::Matrix3x2F::Scale(rect.w / 24, rect.h / 24) *
                              D2D1::Matrix3x2F::Rotation(rotation, D2D1::Point2F(rect.w / 2, rect.h / 2)) *
                              D2D1::Matrix3x2F::Translation(rect.x, rect.y));
        brush_->SetColor(rgba(c));
        target_->DrawGeometry(path.Get(), brush_.Get(), weight, stroke_.Get());
        target_->SetTransform(D2D1::Matrix3x2F::Identity());
    }
    void caption_icon(Icon which, Rect button, COLORREF tint) {
        // Lucide paths have different intrinsic bounds. Match the visible ink
        // to 10 DIPs and keep the final stroke at 1.2 DIPs after scaling.
        const float bounds = which == Icon::Minimize  ? 14.f
                             : which == Icon::Close   ? 12.f
                             : which == Icon::Restore ? 20.f
                                                      : 18.f;
        const float side = 24.f * 10.f / bounds;
        icon(which, {button.x + (button.w - side) / 2, button.y + (button.h - side) / 2, side, side}, tint,
             1.2f * 24.f / side);
    }
    void logo(Rect rect) {
        const auto outer = rect.inset(rect.w / 32.f);
        gradient(outer, RGB(59, 145, 113), Deep, rect.w * 17.f / 64.f);
        outline(outer.inset(rect.w * .012f), RGB(105, 166, 133), rect.w * 16.f / 64.f, rect.w * .023f);
        icon(Icon::AppMark, rect.inset(rect.w * .1875f), White, 2.4f);
    }
};
} // namespace scau::desktop::visual
