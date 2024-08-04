module Main exposing (main)

import Browser
import Html exposing (..)
import Html.Attributes exposing (class, src, style)
import Html.Events exposing (onClick)


main : Program () Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , subscriptions = subscriptions
        , view = view
        }


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none


type alias Model =
    {}


init : () -> ( Model, Cmd Msg )
init _ =
    ( {}, Cmd.none )


type Msg
    = Hi


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Hi ->
            init ()


view : Model -> Html Msg
view model =
    div
        []
        [ text "Hello, world!" ]
